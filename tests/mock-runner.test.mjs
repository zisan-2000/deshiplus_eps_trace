import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runMockDiagnostic, assertMockRuntimeSafety } from '../src/mock-runner.mjs';
import { AttemptLedger, MOCK_SCOPE } from '../src/attempt-ledger.mjs';
import { sanitizedCombinedReport } from '../src/mock-evidence.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const tmpRoot=path.join(root,'tmp');
function workspace(t,name='mock-test-'){
  fs.mkdirSync(tmpRoot,{recursive:true});const dir=fs.mkdtempSync(path.join(tmpRoot,name));
  t.after(()=>{fs.rmSync(dir,{recursive:true,force:true});if(fs.existsSync(tmpRoot)&&!fs.readdirSync(tmpRoot).length)fs.rmdirSync(tmpRoot);});
  return dir;
}
test('mock runner validates AUTH -> INITIALIZE -> hosted simulation -> exact STATUS success',async t=>{
  const base=workspace(t),result=await runMockDiagnostic({scenario:'success',simulateHostedCompletion:true,
    ledgerDirectory:path.join(base,'ledger'),outputParent:path.join(base,'evidence')});
  assert.equal(result.report.outcome,'MOCK_SUCCESS');
  assert.deepEqual(result.report.steps.map(s=>[s.name,s.httpStatus,s.code,s.paymentVerified]),[
    ['AUTH',200,'AUTH_ACCEPTED',false],['INITIALIZE',200,'INITIALIZE_ACCEPTED',false],['STATUS',200,'STATUS_SUCCESS_CONFIRMED',true]]);
  assert.equal(result.report.capture,null);assert.equal(result.report.liveExecutionDecision,'NO_GO');
  const text=fs.readFileSync(path.join(result.directory,'combined-report.json'),'utf8');
  for(const value of ['SYNTHETIC_EPS_PASSWORD','SYNTHETIC_UTF8_HASH_KEY','SYNTHETIC_OPAQUE_AUTH_TOKEN','EPS Diagnostic Synthetic Customer','eps-diagnostic@example.com','DPEPS-'])assert.ok(!text.includes(value));
});
test('hosted-payment pause is durable and explicit resume skips AUTH and INITIALIZE',async t=>{
  const base=workspace(t),ledgerDirectory=path.join(base,'ledger'),outputParent=path.join(base,'evidence');
  const paused=await runMockDiagnostic({scenario:'success',simulateHostedCompletion:false,ledgerDirectory,outputParent});
  assert.equal(paused.report.outcome,'PAUSED');assert.deepEqual(paused.report.steps.map(s=>s.name),['AUTH','INITIALIZE']);
  assert.equal(new AttemptLedger(ledgerDirectory).inspect(paused.attemptId).phase,'AWAITING_HOSTED_PAYMENT');
  const resumed=await runMockDiagnostic({scenario:'success',simulateHostedCompletion:true,resumeAttempt:paused.attemptId,ledgerDirectory,outputParent});
  assert.equal(resumed.report.outcome,'MOCK_SUCCESS');assert.deepEqual(resumed.report.steps.map(s=>s.name),['STATUS']);
  assert.ok(resumed.report.events.includes('RESUMED_WITHOUT_AUTH_OR_INITIALIZE'));
});
test('strict STATUS outcomes distinguish HTTP, gateway, reference, amount and pending failures',async t=>{
  const base=workspace(t),ledgerDirectory=path.join(base,'ledger'),outputParent=path.join(base,'evidence');
  const expected={pending:[200,'STATUS_NOT_CONFIRMED','STATUS_UNCONFIRMED'],http101:[101,'HTTP_STATUS_REJECTED','FAILED'],
    gateway101:[200,'GATEWAY_ERROR_REPORTED','FAILED'],'reference-mismatch':[200,'STATUS_TRANSACTION_MISMATCH','FAILED'],
    'amount-mismatch':[200,'STATUS_AMOUNT_MISMATCH','FAILED'],malformed:[200,'INVALID_JSON','FAILED'],
    oversize:[200,'JSON_SIZE_LIMIT_EXCEEDED','FAILED'],redirect:[302,'HTTP_STATUS_REJECTED','FAILED'],timeout:[null,'MOCK_HTTP_TIMEOUT','FAILED']};
  for(const [scenario,[status,code,outcome]] of Object.entries(expected)){
    const result=await runMockDiagnostic({scenario,simulateHostedCompletion:true,ledgerDirectory,outputParent});
    const step=result.report.steps.at(-1);assert.equal(step.name,'STATUS');assert.equal(step.httpStatus,status,scenario);
    assert.equal(step.code,code,scenario);assert.equal(step.paymentVerified,false,scenario);assert.equal(result.report.outcome,outcome,scenario);
  }
});
test('initialize uncertainty is persisted and neither resume nor duplicate identity can initialize again',async t=>{
  const base=workspace(t),ledgerDirectory=path.join(base,'ledger'),outputParent=path.join(base,'evidence');
  const result=await runMockDiagnostic({scenario:'initialize-timeout',simulateHostedCompletion:true,ledgerDirectory,outputParent});
  const ledger=new AttemptLedger(ledgerDirectory),attempt=ledger.inspect(result.attemptId);
  assert.equal(attempt.phase,'INITIALIZE_UNCERTAIN');
  await assert.rejects(runMockDiagnostic({scenario:'success',simulateHostedCompletion:true,resumeAttempt:result.attemptId,ledgerDirectory,outputParent}),/MOCK_RESUME_PHASE_REJECTED/);
  assert.throws(()=>ledger.reserve(attempt),/LEDGER_DUPLICATE_INITIALIZE_FORBIDDEN/);
});
test('atomic cross-process reservation permits at most one claimant',async t=>{
  const base=workspace(t),ledgerDirectory=path.join(base,'ledger');new AttemptLedger(ledgerDirectory);
  const transaction='00000000009999999999999',order='DPEPS-'+transaction+'-0123456789abcdef';
  const run=()=>new Promise(resolve=>{const child=spawn(process.execPath,['tests/ledger-child.mjs',ledgerDirectory,transaction,order],
    {cwd:root,env:process.env,windowsHide:true,stdio:['ignore','pipe','ignore']});let output='';child.stdout.on('data',c=>output+=c);child.on('close',()=>resolve(output));});
  const results=await Promise.all([run(),run()]);
  assert.equal(results.filter(value=>value==='RESERVED').length,1);
  assert.ok(results.some(value=>['LEDGER_DUPLICATE_INITIALIZE_FORBIDDEN','LEDGER_LOCKED_RECONCILIATION_REQUIRED'].includes(value)));
});
test('torn journal and stale lock fail closed and ledger contains no credentials or customer data',t=>{
  const base=workspace(t),ledgerDirectory=path.join(base,'ledger'),ledger=new AttemptLedger(ledgerDirectory);
  const transaction='00000000008888888888888',order='DPEPS-'+transaction+'-0123456789abcdef',attempt=ledger.reserve({merchantTransactionId:transaction,customerOrderId:order,amount:'10.00'});
  const journal=fs.readFileSync(path.join(ledgerDirectory,'events.ndjson'),'utf8');
  assert.ok(journal.includes(MOCK_SCOPE));for(const value of ['PASSWORD','HASH_KEY','TOKEN','CUSTOMER_NAME','customerEmail'])assert.ok(!journal.includes(value));
  fs.writeFileSync(path.join(ledgerDirectory,'writer.lock'),'stale',{flag:'wx'});
  assert.throws(()=>ledger.inspect(attempt.id),/LEDGER_LOCKED_RECONCILIATION_REQUIRED/);fs.unlinkSync(path.join(ledgerDirectory,'writer.lock'));
  fs.appendFileSync(path.join(ledgerDirectory,'events.ndjson'),'{');assert.throws(()=>ledger.inspect(attempt.id),/LEDGER_CORRUPT/);
  assert.equal(fs.existsSync(path.join(ledgerDirectory,'writer.lock')),true);
});
test('combined report is constructed from an allowlist and cannot echo arbitrary private fields',()=>{
  const secret='SYNTHETIC_PRIVATE_SENTINEL';
  const report=JSON.stringify(sanitizedCombinedReport({attemptId:secret,outcome:secret,steps:[{name:'AUTH',httpStatus:200,outcome:secret,code:secret,timing:{source:secret},body:secret,token:secret}],events:[secret],capture:{packetCount:1,private:secret}}));
  assert.ok(!report.includes(secret));assert.ok(!report.includes('body'));assert.ok(!report.includes('token'));
});
test('mock TLS execution rejects key logging and certificate bypass settings',()=>{
  for(const environment of [{SSLKEYLOGFILE:'synthetic-path'},{NODE_OPTIONS:'--tls-keylog=synthetic-path'},
    {NODE_TLS_REJECT_UNAUTHORIZED:'0'}])assert.throws(()=>assertMockRuntimeSafety(environment),/MOCK_UNSAFE_TLS_ENVIRONMENT/);
  assert.equal(assertMockRuntimeSafety({}),true);
});
