import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {REQUIRED_ENV_NAMES} from '../src/eps-contract.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const fixture=fileURLToPath(new URL('./environment-fixture.ps1',import.meta.url));
const guard=fileURLToPath(new URL('../scripts/offline-validation-guard.cjs',import.meta.url));
const cleanEnv=()=>Object.fromEntries(Object.entries(process.env).filter(([k])=>!/^EPS_|^(NODE_OPTIONS|SSLKEYLOGFILE|NODE_TLS_REJECT_UNAUTHORIZED)$/i.test(k)));
for(const shell of ['powershell.exe','C:\\Program Files\\PowerShell\\7\\pwsh.exe']) {
 for(const scenario of ['valid','blocked','existing','token','tls','plaintext','throw','amount','missing','credential','nul','unicode','long','callback']) test(shell.split('\\').at(-1)+' secure helper '+scenario,()=>{
   const run=spawnSync(shell,['-NoLogo','-NoProfile','-NonInteractive','-File',fixture,scenario],{cwd:root,env:cleanEnv(),encoding:'utf8',windowsHide:true,timeout:25000});
   assert.equal(run.status,0,'PowerShell fixture did not complete');
   assert.equal(run.stderr,'','No raw errors may be displayed');
   for(const sentinel of ['synthetic-password','SYNTHETIC_PRIVATE','synthetic-utf8-key','https://','DPEPS-']) assert.ok(!run.stdout.includes(sentinel),'Private output leaked');
   const report=JSON.parse(run.stdout.trim()); assert.deepEqual([...report.Names].sort(),[...REQUIRED_ENV_NAMES].sort());
   assert.equal(report.Result.ExecutionReady,false);
   if(scenario==='valid') {
     assert.equal(report.Result.Success,true); assert.equal(report.Result.Published,true);
     for(const key of ['Complete','IdentityValid','AmountCanonical','RepeatBlocked','Unique']) assert.equal(report[key],true,key);
   } else {
     assert.equal(report.Result.Success,false);assert.equal(report.Result.Published,false);assert.equal(report.PreviousRestored,true);
     if(['blocked','existing','token','tls','plaintext','throw'].includes(scenario)) assert.equal(report.NoCredentialPrompt,true);
     if(scenario==='blocked') {assert.equal(report.PromptCount,1);assert.equal(report.Result.Code,'ISOLATED_CALLBACK_RECEIVER_UNAVAILABLE_OR_UNAPPROVED');}
     if(scenario==='missing') assert.ok(report.Result.Issues.includes('ENV_MISSING:EPS_PASSWORD'));
     if(['credential','nul','unicode'].includes(scenario)) assert.ok(report.Result.Issues.includes('ENV_INVALID:EPS_PASSWORD'));
     if(scenario==='long') assert.equal(report.Result.Code,'PRIVATE_INPUT_TOO_LONG');
   }
 });
}
for(const [name,expression] of [
 ['HTTPS',"require('node:https').request('https://invalid.example')"],
 ['fetch',"fetch('https://invalid.example')"],['DNS',"require('node:dns').lookup('invalid.example',()=>{})"],
 ['TCP',"require('node:net').connect(443,'invalid.example')"],['child process',"require('node:child_process').spawn('node',[])"],
 ['ESM import',"import('node:https').then(m=>m.request('https://invalid.example'))"]
]) test('private validation guard blocks '+name+' before any operation',()=>{
 const r=spawnSync(process.execPath,['--require',guard,'-e',expression],{env:cleanEnv(),encoding:'utf8',windowsHide:true,timeout:5000});
 assert.equal(r.status,1);assert.match(r.stderr,/PRIVATE_PREFLIGHT_NETWORK_OR_PROCESS_FORBIDDEN/);
});
test('production helper uses hidden prompts, fixed offline validator and process-only environment',()=>{
 const source=fs.readFileSync(new URL('../scripts/EpsSandboxEnvironment.psm1',import.meta.url),'utf8');
 assert.match(source,/Read-Host -Prompt \$Prompt -AsSecureString/);
 assert.match(source,/ZeroFreeBSTR/); assert.match(source,/validate --config/);
 assert.doesNotMatch(source,/Invoke-RestMethod|Invoke-WebRequest|Set-Content|Out-File|WriteAll|Export-Clixml|ConvertFrom-SecureString|-AsPlainText/);
 assert.doesNotMatch(source,/SetEnvironmentVariable\([^\n]*(?:'User'|'Machine')/);
 assert.match(source,/EnvironmentVariables\.Clear\(\)/);
});
