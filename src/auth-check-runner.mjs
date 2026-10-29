import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { loadConfig, validateConfig } from './config.mjs';
import { validateEpsResponse } from './response-contract.mjs';
import { createAuthOnlySandboxExchange, AUTH_ONLY_ENDPOINT } from './auth-only-http.mjs';
import { captureAuthOnly } from './auth-only-capture.mjs';
import { ownedDirectory, writeExclusive } from './workspace-storage.mjs';

export const AUTH_ONLY_CONFIRMATION='EPS_AUTH_ONLY_EXPLICITLY_AUTHORIZED';
const safeCode=error=>/^AUTH_(?:ONLY|CAPTURE)_[A-Z0-9_]+$/.test(error?.message??'')?error.message:'AUTH_ONLY_DIAGNOSTIC_FAILED';
const validSecret=value=>typeof value==='string'&&value.length>0&&value.length<=4096&&!/[\x00-\x1f\x7f]/.test(value);
const dispositions=new Set(['NOT_SENT','UNCERTAIN','SENT']);
const stages=new Set(['CAPTURE_INTERFACE_INVENTORY','CAPTURE_TOOL_LAUNCH','CAPTURE_READINESS','REQUEST_PREPARATION','DNS','TCP','TLS','HTTP_RESPONSE','RESPONSE_VALIDATION','CAPTURE_FINALIZATION','COMPLETE']);
const authResultCodes=new Set(['AUTH_ACCEPTED','AUTH_TOKEN_INVALID','ERROR_FIELD_TYPE_INVALID','GATEWAY_ERROR_REPORTED',
  'HTTP_STATUS_INVALID','HTTP_STATUS_REJECTED','JSON_DOCUMENT_REQUIRED','JSON_SIZE_LIMIT_EXCEEDED','DUPLICATE_JSON_KEY',
  'JSON_DEPTH_LIMIT_EXCEEDED','INVALID_UTF8','INVALID_JSON','JSON_OBJECT_REQUIRED']);
const safeResultCode=value=>authResultCodes.has(value)?value:'AUTH_ONLY_RESPONSE_INVALID';

export function sanitizedAuthReport({raw,result,capture,error,failureStage,requestDisposition='NOT_SENT',evidenceScope='EPS_SANDBOX_AUTH_ONLY'}={}) {
  const timing=raw?.timing??{};const number=value=>Number.isFinite(value)&&value>=0?value:null;
  const local=evidenceScope==='LOCAL_LOOPBACK_AUTH_ONLY_NOT_EPS';
  const passed=result?.accepted===true&&!!capture&&!error;
  const disposition=dispositions.has(requestDisposition)?requestDisposition:'UNCERTAIN';
  const stage=stages.has(failureStage)?failureStage:(passed?'COMPLETE':'REQUEST_PREPARATION');
  const errorCode=/^AUTH_(?:ONLY|CAPTURE)_[A-Z0-9_]+$/.test(error??'')?error:null;
  return {schemaVersion:2,stage:'STEP_7C_AUTH_ONLY',evidenceScope,outcome:passed?'PASS':'FAIL',
    code:errorCode??(result?safeResultCode(result.code):'AUTH_ONLY_UNCONFIRMED'),failureStage:stage,requestDisposition:disposition,
    request:{method:'POST',endpoint:AUTH_ONLY_ENDPOINT,attempts:disposition==='NOT_SENT'?0:1},
    response:{httpStatus:Number.isInteger(raw?.httpStatus)?raw.httpStatus:null,authAccepted:result?.accepted===true},
    timing:{dnsMs:number(timing.dnsMs),tcpConnectMs:number(timing.tcpConnectMs),tlsHandshakeMs:number(timing.tlsHandshakeMs),
      firstByteMs:number(timing.firstByteMs),totalMs:number(timing.totalMs),tlsVerified:timing.tlsVerified===true},
    capture:capture?{ready:capture.ready===true,interface:local?'NpcapLoopback-only':'5',filter:local?'owned-loopback-port-only':'tcp port 443 and host sandboxpgapi.eps.com.bd',file:'session.pcapng',format:'pcapng',
      bytes:number(capture.bytes),packetCount:number(capture.packetCount),readinessBeforeRequest:true}:null,
    captureDiagnostics:null,
    security:{credentialsPrinted:false,credentialsPersisted:false,xHashPersisted:false,tokenPersisted:false,responseBodyPersisted:false,
      tlsKeyLogging:false,rawPayloadReport:false},forbiddenOperations:{initialize:false,status:false,hostedPayment:false,callbacks:false,automaticRetries:0}};
}

export async function runAuthCheck({environment=process.env,exchange,capture=captureAuthOnly,outputParent='evidence/auth-check',evidenceScope='EPS_SANDBOX_AUTH_ONLY'}={}) {
  if(!['EPS_SANDBOX_AUTH_ONLY','LOCAL_LOOPBACK_AUTH_ONLY_NOT_EPS'].includes(evidenceScope))throw Error('AUTH_ONLY_EVIDENCE_SCOPE_INVALID');
  if(environment.EPS_AUTH_ONLY_CONFIRMATION!==AUTH_ONLY_CONFIRMATION)throw Error('AUTH_ONLY_CONFIRMATION_REQUIRED');
  if(environment.SSLKEYLOGFILE||/--tls-keylog(?:=|\s|$)/i.test(environment.NODE_OPTIONS??'')||environment.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('AUTH_ONLY_UNSAFE_TLS_ENVIRONMENT');
  const credentials={username:environment.EPS_USERNAME,password:environment.EPS_PASSWORD,hashKey:environment.EPS_HASH_KEY};
  if(!Object.values(credentials).every(validSecret))throw Error('AUTH_ONLY_CREDENTIAL_INPUT_INVALID');
  const cfg=loadConfig();const issues=validateConfig(cfg);if(issues.length)throw Error('AUTH_ONLY_CONFIGURATION_REJECTED');
  const directory=environment.EPS_AUTH_CAPTURE_DIRECTORY?
    ownedDirectory(environment.EPS_AUTH_CAPTURE_DIRECTORY):
    ownedDirectory(path.join(outputParent,new Date().toISOString().replace(/[:.]/g,'-')+'_'+randomUUID()));
  let raw=null,result=null,captureResult=null,error=null,failureStage='CAPTURE_READINESS',requestDisposition='NOT_SENT';
  try {
    const activeExchange=exchange??createAuthOnlySandboxExchange();
    const wrapped=await capture(cfg,directory,async()=>{
      failureStage='REQUEST_PREPARATION';
      try{raw=await activeExchange(credentials);requestDisposition='SENT';}
      catch(exchangeError){requestDisposition=dispositions.has(exchangeError?.requestDisposition)?exchangeError.requestDisposition:'UNCERTAIN';
        failureStage=stages.has(exchangeError?.failureStage)?exchangeError.failureStage:'HTTP_RESPONSE';
        raw={timing:exchangeError?.timing};throw exchangeError;}
      failureStage='RESPONSE_VALIDATION';result=validateEpsResponse('AUTH',raw,{});return result;
    },{environment});
    captureResult=wrapped.capture;
    failureStage=result?.accepted===true?'COMPLETE':'RESPONSE_VALIDATION';
  } catch(caught){error=safeCode(caught);captureResult=caught?.capture??captureResult;
    if(stages.has(caught?.failureStage))failureStage=caught.failureStage;
    if(result||Number.isInteger(raw?.httpStatus))requestDisposition='SENT';
    if(/^AUTH_CAPTURE_/.test(error)&&requestDisposition!=='NOT_SENT')failureStage='CAPTURE_FINALIZATION';}
  const report=sanitizedAuthReport({raw,result,capture:captureResult,error,failureStage,requestDisposition,evidenceScope});
  writeExclusive(path.join(directory,'combined-report.json'),JSON.stringify(report,null,2)+'\n');
  return {directory,report};
}
