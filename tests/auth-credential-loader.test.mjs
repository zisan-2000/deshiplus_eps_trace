import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const cleanEnvironment=Object.fromEntries(Object.entries(process.env).filter(([name])=>!/^EPS_/i.test(name)));

test('credential loader uses only temporary synthetic values, preserves special characters and fails closed',()=>{
  const run=spawnSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',
    path.join(root,'tests/auth-credential-loader-fixture.ps1')],{cwd:root,env:cleanEnvironment,encoding:'utf8',windowsHide:true,timeout:20000});
  assert.equal(run.status,0,run.stderr||'credential loader fixture failed');
  const result=JSON.parse(run.stdout.trim());
  assert.deepEqual(result,{parsed:true,specialCharacters:true,authOnly:true,conflictRejected:true,duplicateRejected:true,unknownRejected:true,outputSanitized:true});
  assert.doesNotMatch(run.stdout,/SYNTHETIC_USER|p@ss|HASH#KEY|SYNTHETIC_MERCHANT|SYNTHETIC_STORE/);
});

test('.env.local is ignored, example exceptions are allowed, and offline tests do not read the project credential file',()=>{
  const ignore=fs.readFileSync(path.join(root,'.gitignore'),'utf8').split(/\r?\n/);
  for(const rule of ['.env','.env.local','.env.*.local','.env.*','!.env.example','!.env.*.example'])assert.ok(ignore.includes(rule),`missing ${rule}`);
  const fixture=fs.readFileSync(path.join(root,'tests/auth-credential-loader-fixture.ps1'),'utf8');
  assert.match(fixture,/tmp\\auth-env-test-/);assert.doesNotMatch(fixture,/Join-Path \$root '\.env\.local'/);
});
