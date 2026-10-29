import { runMockDiagnostic } from '../src/mock-runner.mjs';
try {
  const result=await runMockDiagnostic({scenario:'success',simulateHostedCompletion:true,captureLocal:true});
  console.log(JSON.stringify({outcome:result.report.outcome,evidenceDirectory:result.directory,
    combinedReport:'combined-report.json',pcap:'session.pcapng',liveExecutionDecision:result.report.liveExecutionDecision},null,2));
  process.exitCode=result.report.outcome==='MOCK_SUCCESS'?0:1;
} catch(error) {
  const known=new Set(['MOCK_CONFIGURATION_REJECTED','MOCK_CAPTURE_OR_FLOW_FAILED','MOCK_LEDGER_RECONCILIATION_REQUIRED','MOCK_UNSAFE_TLS_ENVIRONMENT']);
  console.error(JSON.stringify({error:known.has(error.message)?error.message:'MOCK_EVIDENCE_FAILED'}));
  process.exitCode=1;
}
