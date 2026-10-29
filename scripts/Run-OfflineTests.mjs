import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const cleanEnvironment=Object.fromEntries(Object.entries(process.env).filter(([name])=>
  !/^EPS_/i.test(name)&&!['SSLKEYLOGFILE','NODE_OPTIONS','NODE_TLS_REJECT_UNAUTHORIZED'].includes(name.toUpperCase())));
const groups=[
  ['--require','./tests/no-network.cjs','--test','--test-concurrency=1','tests/setup.test.mjs','tests/contract.test.mjs','tests/readiness.test.mjs','tests/security.test.mjs','tests/environment.test.mjs','tests/powershell-environment.test.mjs','tests/mock-runner.test.mjs','tests/live-preparation.test.mjs','tests/auth-check.test.mjs','tests/auth-credential-loader.test.mjs','tests/auth-capture-readiness.test.mjs'],
  ['--test','--test-concurrency=1','tests/auth-check-local.test.mjs'],
  ['--test','--test-concurrency=1','tests/live-local.test.mjs'],
  ['--test','--test-concurrency=1','tests/mock-local.test.mjs']
];
let failed=false;
for(const args of groups){
  const result=spawnSync(process.execPath,args,{cwd:root,env:cleanEnvironment,stdio:'inherit',windowsHide:true,shell:false});
  if(result.status!==0||result.error){failed=true;break;}
}
process.exitCode=failed?1:0;
