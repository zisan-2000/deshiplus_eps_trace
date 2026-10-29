import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runMockDiagnostic } from '../src/mock-runner.mjs';
import { hasPcapngInterface } from '../src/capture-readiness.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),tmpRoot=path.join(root,'tmp');
function workspace(t){fs.mkdirSync(tmpRoot,{recursive:true});const dir=fs.mkdtempSync(path.join(tmpRoot,'mock-local-'));
  t.after(()=>{fs.rmSync(dir,{recursive:true,force:true});if(fs.existsSync(tmpRoot)&&!fs.readdirSync(tmpRoot).length)fs.rmdirSync(tmpRoot);});return dir;}
test('owned TLS loopback produces sanitized timing report and readable PCAPNG',async t=>{
  const base=workspace(t),result=await runMockDiagnostic({scenario:'success',simulateHostedCompletion:true,captureLocal:true,
    ledgerDirectory:path.join(base,'ledger'),outputParent:path.join(base,'evidence')});
  assert.equal(result.report.outcome,'MOCK_SUCCESS');assert.ok(result.report.capture.packetCount>0);
  assert.ok(result.report.capture.tcpStreamCount>0);assert.ok(result.report.capture.tlsRecordPackets>0);
  assert.equal(result.report.capture.sensitivePlaintextFound,false);
  for(const step of result.report.steps){assert.equal(step.timing.source,'local-tls-measurement');assert.equal(step.timing.dnsPerformed,false);
    assert.equal(step.timing.tlsVerified,true);assert.ok(step.timing.tcpConnectMs>=0);assert.ok(step.timing.tlsHandshakeMs>=0);}
  const pcap=path.join(result.directory,'session.pcapng'),report=path.join(result.directory,'combined-report.json');
  assert.equal(hasPcapngInterface(pcap),true);assert.equal(fs.existsSync(report),true);
  const bytes=fs.readFileSync(pcap),text=fs.readFileSync(report,'utf8');
  for(const value of ['SYNTHETIC_EPS_PASSWORD','SYNTHETIC_UTF8_HASH_KEY','SYNTHETIC_OPAQUE_AUTH_TOKEN','EPS Diagnostic Synthetic Customer','eps-diagnostic@example.com','DPEPS-']){
    assert.equal(bytes.includes(Buffer.from(value)),false);assert.equal(text.includes(value),false);
  }
});
test('local TLS mock enforces timeout without retry and keeps live decision NO-GO',async t=>{
  const base=workspace(t),result=await runMockDiagnostic({scenario:'timeout',simulateHostedCompletion:true,localTls:true,
    ledgerDirectory:path.join(base,'ledger'),outputParent:path.join(base,'evidence')});
  assert.equal(result.report.outcome,'FAILED');assert.equal(result.report.steps.at(-1).code,'MOCK_HTTP_TIMEOUT');
  assert.equal(result.report.safety.automaticRetries,0);assert.equal(result.report.liveExecutionDecision,'NO_GO');
});
