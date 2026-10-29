import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { loadConfig, validateConfig } from './config.mjs';
import { ownedDirectory } from './workspace-storage.mjs';
import { AttemptLedger } from './attempt-ledger.mjs';
import { createMockContext, mockRequest } from './mock-data.mjs';
import { createMemoryMock, createLoopbackTlsMock, exchangeMock, simulateMockHostedCompletion, closeMockTransport, MOCK_SCENARIOS } from './mock-transport.mjs';
import { validateEpsResponse } from './response-contract.mjs';
import { captureMockExchange, writeCombinedReport } from './mock-evidence.mjs';

export function assertMockRuntimeSafety(environment=process.env) {
  if(environment.SSLKEYLOGFILE||/--tls-keylog(?:=|\s|$)/i.test(environment.NODE_OPTIONS??'')||
    environment.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('MOCK_UNSAFE_TLS_ENVIRONMENT');
  return true;
}

export async function runMockDiagnostic(options={}) {
  assertMockRuntimeSafety();
  const allowed=['scenario','simulateHostedCompletion','captureLocal','localTls','resumeAttempt','ledgerDirectory','outputParent'];
  if(Object.keys(options).some(k=>!allowed.includes(k))||
    ['captureLocal','localTls','simulateHostedCompletion'].some(k=>options[k]!==undefined&&typeof options[k]!=='boolean')||
    !MOCK_SCENARIOS.includes(options.scenario??'success'))throw Error('MOCK_OPTIONS_REJECTED');
  const cfg=loadConfig();if(validateConfig(cfg).length)throw Error('MOCK_CONFIGURATION_REJECTED');
  const ledger=new AttemptLedger(options.ledgerDirectory);
  const resume=options.resumeAttempt!==undefined;
  if(resume&&(!/^[a-f0-9-]{36}$/.test(options.resumeAttempt)||options.simulateHostedCompletion!==true))throw Error('MOCK_RESUME_REQUIRES_EXPLICIT_SIMULATION');
  let attempt=resume?ledger.inspect(options.resumeAttempt):null;
  if(resume&&!['AWAITING_HOSTED_PAYMENT','HOSTED_COMPLETION_SIMULATED'].includes(attempt.phase))throw Error('MOCK_RESUME_PHASE_REJECTED');
  const context=createMockContext(attempt);
  if(resume)context.token='SYNTHETIC_OPAQUE_AUTH_TOKEN'; // Synthetic session only; never persisted/refreshed against EPS.
  if(!attempt)attempt=ledger.reserve(context);
  const directory=ownedDirectory(path.join(options.outputParent??'evidence/mock',new Date().toISOString().replace(/[:.]/g,'-')+'_'+randomUUID()));
  const steps=[],events=[resume?'RESUMED_WITHOUT_AUTH_OR_INITIALIZE':'ATTEMPT_RESERVED'];let outcome='FAILED',capture=null;
  const transport=options.captureLocal||options.localTls?await createLoopbackTlsMock(context,options.scenario):createMemoryMock(context,options.scenario);
  const exchange=async name=>{
    try{
      const raw=await exchangeMock(transport,name,mockRequest(name,context));
      const result=validateEpsResponse(name,raw,context);
      steps.push({name,httpStatus:raw.httpStatus,...result,timing:raw.timing});
      return result;
    }catch(error){
      const code=['MOCK_HTTP_TIMEOUT','MOCK_RESPONSE_SIZE_LIMIT','MOCK_RESPONSE_ABORTED','MOCK_REQUEST_CONTRACT_REJECTED'].includes(error.message)?error.message:'MOCK_TRANSPORT_FAILURE';
      const result={accepted:false,outcome:'TRANSPORT_FAILURE',code,paymentVerified:false};steps.push({name,httpStatus:null,...result});return result;
    }
  };
  const flow=async()=>{
    if(!resume){
      const auth=await exchange('AUTH');ledger.transition(attempt.id,auth.accepted?'AUTH_OK':'AUTH_FAIL');if(!auth.accepted)return;
      ledger.transition(attempt.id,'CLAIM_INITIALIZE');events.push('INITIALIZE_DURABLY_CLAIMED');
      const init=await exchange('INITIALIZE');ledger.transition(attempt.id,init.accepted?'INITIALIZE_OK':'INITIALIZE_UNCERTAIN');if(!init.accepted)return;
    }
    events.push('HOSTED_PAYMENT_PAUSED');outcome='PAUSED';
    if(options.simulateHostedCompletion!==true)return;
    if(ledger.inspect(attempt.id).phase==='AWAITING_HOSTED_PAYMENT')ledger.transition(attempt.id,'HOSTED_SIMULATED');
    simulateMockHostedCompletion(transport);events.push('HOSTED_COMPLETION_EXPLICITLY_SIMULATED');
    ledger.transition(attempt.id,'CLAIM_STATUS');events.push('STATUS_DURABLY_CLAIMED');
    const status=await exchange('STATUS');ledger.transition(attempt.id,status.paymentVerified?'STATUS_SUCCESS':'STATUS_UNCONFIRMED');
    outcome=status.paymentVerified?'MOCK_SUCCESS':status.outcome==='PENDING'?'STATUS_UNCONFIRMED':'FAILED';
  };
  try{
    if(options.captureLocal)capture=await captureMockExchange(transport,cfg,directory,flow);else await flow();
  }catch(error){
    outcome='FAILED';
    writeCombinedReport(directory,{attemptId:attempt.id,outcome,steps,events,capture:null});
    throw Error(error.message.startsWith('LEDGER_')?'MOCK_LEDGER_RECONCILIATION_REQUIRED':'MOCK_CAPTURE_OR_FLOW_FAILED');
  }finally{await closeMockTransport(transport);context.token=null;context.hashKey=null;context.password=null;}
  const report=writeCombinedReport(directory,{attemptId:attempt.id,outcome,steps,events,capture});
  return {report,directory,attemptId:attempt.id};
}
