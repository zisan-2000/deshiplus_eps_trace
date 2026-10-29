import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUTH_ONLY_ENDPOINT } from '../src/auth-only-http.mjs';
import { AUTH_CAPTURE_PLAN, AUTH_CAPTURE_OWNER, captureAuthOnly } from '../src/auth-only-capture.mjs';
import { sanitizedAuthReport, runAuthCheck, AUTH_ONLY_CONFIRMATION } from '../src/auth-check-runner.mjs';
import { createLocalConfig } from '../src/eps-contract.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
function header(){const b=Buffer.alloc(48);b.writeUInt32LE(0x0a0d0d0a,0);b.writeUInt32LE(28,4);b.writeUInt32LE(0x1a2b3c4d,8);b.writeUInt32LE(1,12);b.writeUInt32LE(0xffffffff,16);b.writeUInt32LE(0xffffffff,20);b.writeUInt32LE(28,24);b.writeUInt32LE(1,28);b.writeUInt32LE(20,32);b.writeUInt32LE(1,36);b.writeUInt32LE(65535,40);b.writeUInt32LE(20,44);return b;}
function captureEnvironment(directory){return{EPS_AUTH_CAPTURE_OWNER:AUTH_CAPTURE_OWNER,EPS_AUTH_CAPTURE_DIRECTORY:directory,
  EPS_AUTH_CAPTURE_INTERFACE:'5',EPS_AUTH_CAPTURE_FILTER:AUTH_CAPTURE_PLAN.filter,EPS_AUTH_CAPTURE_READY_AT:new Date().toISOString()};}
function syntheticEnvironment(){return{EPS_AUTH_ONLY_CONFIRMATION:AUTH_ONLY_CONFIRMATION,EPS_USERNAME:'SYNTHETIC_USER',EPS_PASSWORD:'SYNTHETIC_PASSWORD',EPS_HASH_KEY:'SYNTHETIC_HASH_KEY'};}
function syntheticRaw(body={token:'SYNTHETIC_RETURNED_TOKEN',errorCode:null,errorMessage:null}){return{httpStatus:200,body:JSON.stringify(body),requestDisposition:'SENT',
  timing:{dnsMs:1,tcpConnectMs:2,tlsHandshakeMs:3,firstByteMs:4,totalMs:5,tlsVerified:true}};}
function readyCapture(){return async(_cfg,directory,flow)=>{const value=await flow();fs.writeFileSync(path.join(directory,'session.pcapng'),header());return{value,capture:{ready:true,bytes:48,packetCount:1}};};}
function outputParent(t,name){const parent=path.join('tmp',name+'-'+Date.now()+'-'+Math.random().toString(16).slice(2));const absolute=path.join(root,parent);t.after(()=>fs.rmSync(absolute,{recursive:true,force:true}));return parent;}

test('AUTH-only constants and npm entry cannot select payment endpoints',()=>{
  assert.equal(AUTH_ONLY_ENDPOINT,'https://sandboxpgapi.eps.com.bd/v1/Auth/GetToken');
  assert.deepEqual(AUTH_CAPTURE_PLAN,{interface:'5',filter:'tcp port 443 and host sandboxpgapi.eps.com.bd',format:'pcapng',fileName:'session.pcapng',durationSeconds:25});
  const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
  assert.match(pkg.scripts['auth:check'],/Invoke-EpsAuthCheck\.ps1$/);assert.match(pkg.scripts.trace,/cli\.mjs trace$/);assert.equal(pkg.scripts.auth,undefined);
  for(const file of ['src/auth-only-http.mjs','src/auth-check-cli.mjs','scripts/Invoke-EpsAuthCheck.ps1']){
    const source=fs.readFileSync(path.join(root,file),'utf8');assert.doesNotMatch(source,/InitializeEPS|CheckMerchantTransactionStatus|successUrl|failUrl|cancelUrl/);
  }
});

test('PowerShell-owned capture context gates the request on an existing complete PCAPNG',async t=>{
  fs.mkdirSync(path.join(root,'tmp'),{recursive:true});const directory=fs.mkdtempSync(path.join(root,'tmp','auth-capture-'));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  fs.writeFileSync(path.join(directory,'session.pcapng'),header());let called=false;
  const result=await captureAuthOnly(createLocalConfig(),directory,async()=>{called=true;return 'SAFE';},{environment:captureEnvironment(directory)});
  assert.equal(called,true);assert.equal(result.capture.ready,true);assert.equal(result.capture.interface,'5');
  const source=fs.readFileSync(path.join(root,'src/auth-only-capture.mjs'),'utf8');
  assert.doesNotMatch(source,/node:child_process|\bspawn(?:Sync)?\s*\(/);assert.match(source,/PowerShell AUTH wrapper owns/);
});

test('capture readiness failure is NOT_SENT and never invokes AUTH flow',async t=>{
  fs.mkdirSync(path.join(root,'tmp'),{recursive:true});const directory=fs.mkdtempSync(path.join(root,'tmp','auth-not-ready-'));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));let called=false;
  await assert.rejects(()=>captureAuthOnly(createLocalConfig(),directory,async()=>{called=true;},{environment:captureEnvironment(directory)}),/AUTH_CAPTURE_NOT_READY/);
  assert.equal(called,false);
});

test('sanitized AUTH report allowlist cannot echo credentials, hash, token, provider body or arbitrary errors',()=>{
  const sentinel='SYNTHETIC_PRIVATE_SENTINEL';
  const report=sanitizedAuthReport({raw:{httpStatus:200,body:sentinel,token:sentinel,timing:{dnsMs:1,tcpConnectMs:2,tlsHandshakeMs:3,firstByteMs:4,totalMs:5,tlsVerified:true,private:sentinel}},
    result:{accepted:true,code:'AUTH_ACCEPTED',private:sentinel},capture:{ready:true,bytes:48,packetCount:2,private:sentinel},failureStage:'COMPLETE',requestDisposition:'SENT'});
  const hostile=sanitizedAuthReport({error:sentinel,failureStage:sentinel,requestDisposition:sentinel});
  const text=JSON.stringify([report,hostile]);assert.ok(!text.includes(sentinel));assert.equal(report.response.authAccepted,true);assert.equal(report.security.tokenPersisted,false);
  assert.equal(hostile.code,'AUTH_ONLY_UNCONFIRMED');assert.equal(hostile.requestDisposition,'UNCERTAIN');
});

test('capture launch failure produces a stage-specific NOT_SENT report',async t=>{
  const capture=async()=>{const error=new Error('AUTH_CAPTURE_TOOL_LAUNCH_DENIED');error.failureStage='CAPTURE_TOOL_LAUNCH';throw error;};
  const result=await runAuthCheck({environment:syntheticEnvironment(),exchange:async()=>{throw new Error('FLOW_MUST_NOT_RUN');},capture,outputParent:outputParent(t,'auth-capture-failure')});
  assert.equal(result.report.outcome,'FAIL');assert.equal(result.report.code,'AUTH_CAPTURE_TOOL_LAUNCH_DENIED');
  assert.equal(result.report.failureStage,'CAPTURE_TOOL_LAUNCH');assert.equal(result.report.requestDisposition,'NOT_SENT');assert.equal(result.report.request.attempts,0);
});

test('network failure preserves partial timing and has UNCERTAIN disposition',async t=>{
  const exchange=async()=>{const error=new Error('AUTH_ONLY_TRANSPORT_FAILURE');Object.assign(error,{failureStage:'TLS',requestDisposition:'UNCERTAIN',
    timing:{dnsMs:1.5,tcpConnectMs:3.5,tlsHandshakeMs:null,firstByteMs:null,totalMs:7.5,tlsVerified:false}});throw error;};
  const result=await runAuthCheck({environment:syntheticEnvironment(),exchange,capture:readyCapture(),outputParent:outputParent(t,'auth-network-failure')});
  assert.equal(result.report.code,'AUTH_ONLY_TRANSPORT_FAILURE');assert.equal(result.report.failureStage,'TLS');assert.equal(result.report.requestDisposition,'UNCERTAIN');
  assert.equal(result.report.timing.dnsMs,1.5);assert.equal(result.report.timing.tcpConnectMs,3.5);assert.equal(result.report.timing.totalMs,7.5);
});

test('invalid AUTH response is SENT, sanitized and fails at response validation',async t=>{
  const exchange=async()=>syntheticRaw({token:'',errorCode:null,errorMessage:null,privateProviderField:'PRIVATE_PROVIDER_MESSAGE'});
  const result=await runAuthCheck({environment:syntheticEnvironment(),exchange,capture:readyCapture(),outputParent:outputParent(t,'auth-invalid-response')});
  assert.equal(result.report.outcome,'FAIL');assert.equal(result.report.code,'AUTH_TOKEN_INVALID');
  assert.equal(result.report.failureStage,'RESPONSE_VALIDATION');assert.equal(result.report.requestDisposition,'SENT');
  assert.ok(!JSON.stringify(result.report).includes('PRIVATE_PROVIDER_MESSAGE'));
});

test('runner requires explicit capability phrase and produces only sanitized synthetic evidence',async t=>{
  const environment=syntheticEnvironment();const parent=outputParent(t,'auth-runner');
  const result=await runAuthCheck({environment,exchange:async()=>syntheticRaw(),capture:readyCapture(),outputParent:parent});
  assert.equal(result.report.outcome,'PASS');assert.equal(result.report.failureStage,'COMPLETE');assert.equal(result.report.requestDisposition,'SENT');
  const text=fs.readFileSync(path.join(result.directory,'combined-report.json'),'utf8');
  for(const secret of Object.values(environment).concat('SYNTHETIC_RETURNED_TOKEN'))assert.ok(!text.includes(secret));
  await assert.rejects(()=>runAuthCheck({environment:{...environment,EPS_AUTH_ONLY_CONFIRMATION:'wrong'},exchange:async()=>syntheticRaw(),capture:readyCapture(),outputParent:parent}),/AUTH_ONLY_CONFIRMATION_REQUIRED/);
});

test('PowerShell wrapper owns inventory, launch and readiness before the hidden credential prompts',()=>{
  const source=fs.readFileSync(path.join(root,'scripts/Invoke-EpsAuthCheck.ps1'),'utf8');
  assert.equal((source.match(/Read-Host -Prompt \$item\.Prompt -AsSecureString/g)||[]).length,1);assert.match(source,/foreach\(\$item in/);
  assert.match(source,/ZeroFreeBSTR/);assert.match(source,/EnvironmentVariables\.Clear\(\)/);assert.match(source,/AUTH-ONLY/);
  assert.match(source,/Invoke-OwnedTool \$tshark @\('-D'\)/);assert.match(source,/Get-EpsPcapngStructure -Path \$pcap/);
  assert.match(source,/Read-EpsCredentialFile -Path \(Join-Path \$projectRoot '\.env\.local'\)/);
  assert.match(source,/Resolve-EpsAuthCredentials/);
  assert.match(fs.readFileSync(path.join(root,'scripts/AuthCredentialLoader.psm1'),'utf8'),/AUTH_ONLY_CREDENTIAL_SOURCE_CONFLICT/);
  assert.match(source,/AUTH_CAPTURE_TOOL_LAUNCH_DENIED/);assert.match(source,/AUTH_CAPTURE_INTERFACE_INVENTORY_FAILED/);
  assert.ok(source.indexOf("$readyAt=[DateTime]::UtcNow")<source.indexOf("Read-Host -Prompt $item.Prompt -AsSecureString"));
  assert.ok(source.indexOf("$readyAt=[DateTime]::UtcNow")<source.indexOf("Read-EpsCredentialFile -Path"));
  assert.doesNotMatch(source,/ConvertFrom-SecureString|Invoke-WebRequest|Invoke-RestMethod/);
  assert.doesNotMatch(source,/Write-Host[^\n]*(?:\$plain|\$values|EPS_PASSWORD|EPS_HASH_KEY)/);
});
