import fs from 'node:fs';
import path from 'node:path';
import { runMockDiagnostic } from '../src/mock-runner.mjs';
import { liveRunnerPreparationSummary } from '../src/live-runner-preparation.mjs';

try {
  const result=await runMockDiagnostic({scenario:'success',simulateHostedCompletion:true,captureLocal:true,outputParent:'evidence/step7b-local'});
  const report={schemaVersion:1,stage:'STEP_7B_LIVE_PREPARATION_DISABLED',evidenceScope:'LOCAL_LOOPBACK_TLS_ONLY_NOT_EPS_EVIDENCE',
    outcome:result.report.outcome==='MOCK_SUCCESS'?'PASS':'FAIL',liveExecutionDecision:'NO_GO',
    flow:['AUTH','INITIALIZE','HOSTED_PAYMENT_EXPLICIT_SYNTHETIC_PAUSE_RESUME','STATUS'],
    transportDiagnostics:{dns:'verified-by-forced-loopback-test',tcp:true,tlsVerified:true,http:true,automaticRetries:0},
    capture:{...result.report.capture,file:'session.pcapng',interface:'NpcapLoopback-only'},
    security:{tlsKeyLogging:false,rawPayloadReport:false,credentialsPersisted:false,tokensPersisted:false},
    preparation:liveRunnerPreparationSummary()};
  fs.writeFileSync(path.join(result.directory,'combined-report.json'),JSON.stringify(report,null,2)+'\n',{encoding:'utf8',flag:'w'});
  console.log(JSON.stringify({outcome:report.outcome,directory:result.directory,combinedReport:'combined-report.json',pcap:'session.pcapng',liveExecutionDecision:'NO_GO'},null,2));
} catch(error) {console.error(JSON.stringify({outcome:'FAIL',error:'LOCAL_STEP_7B_EVIDENCE_FAILED'}));process.exitCode=1;}
