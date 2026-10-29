import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const cleanEnvironment=Object.fromEntries(Object.entries(process.env).filter(([name])=>!/^EPS_/i.test(name)));

test('AUTH readiness accepts a live zero-packet PCAPNG without a stderr banner',()=>{
  const run=spawnSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',
    path.join(root,'tests/auth-capture-readiness-fixture.ps1')],{cwd:root,env:cleanEnvironment,encoding:'utf8',windowsHide:true,timeout:20000});
  assert.equal(run.status,0,run.stderr||'AUTH readiness fixture failed');
  assert.deepEqual(JSON.parse(run.stdout.trim()),{zeroPacketReady:true,readyWithoutPackets:true,bannerRequired:false,packetBlockCount:0,
    timeoutReady:false,timeoutState:'TIMEOUT',timeoutHasHeader:false});
});

test('AUTH wrapper keeps the pre-request gate and reports only sanitized capture diagnostics',()=>{
  const source=fs.readFileSync(path.join(root,'scripts/Invoke-EpsAuthCheck.ps1'),'utf8');
  assert.match(source,/Get-EpsCaptureReadinessDecision/);assert.match(source,/if\(\$lastReadinessDecision\.ready\)\{break\}/);
  assert.doesNotMatch(source,/if\(\$banner -and/);assert.match(source,/captureDiagnostics/);
  assert.ok(source.indexOf('$readyAt=[DateTime]::UtcNow')<source.indexOf('Read-EpsCredentialFile -Path'));
  const module=fs.readFileSync(path.join(root,'scripts/AuthCaptureReadiness.psm1'),'utf8');
  assert.match(module,/packetRequiredForReadiness=\$false/);assert.doesNotMatch(module,/stderr(?:Text|Line|Raw)=/i);
});
