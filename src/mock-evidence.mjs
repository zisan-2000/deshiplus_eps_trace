import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runCaptureProbe, localToolEnvironment } from './capture-readiness.mjs';
import { mockTransportInfo } from './mock-transport.mjs';
import { writeExclusive } from './workspace-storage.mjs';
import { executionSafetySummary } from './execution-safety.mjs';
const codes=new Set(['AUTH_ACCEPTED','AUTH_TOKEN_INVALID','INITIALIZE_ACCEPTED','INITIALIZE_REDIRECT_INVALID',
  'INITIALIZE_TRANSACTION_ID_INVALID','GATEWAY_ERROR_REPORTED','STATUS_SUCCESS_CONFIRMED','STATUS_NOT_CONFIRMED',
  'STATUS_TRANSACTION_MISMATCH','STATUS_AMOUNT_MISMATCH','STATUS_FIELD_INVALID','HTTP_STATUS_REJECTED',
  'HTTP_STATUS_INVALID','INVALID_JSON','JSON_SIZE_LIMIT_EXCEEDED','JSON_OBJECT_REQUIRED','MOCK_HTTP_TIMEOUT',
  'MOCK_TRANSPORT_FAILURE','MOCK_RESPONSE_SIZE_LIMIT','MOCK_RESPONSE_ABORTED','MOCK_REQUEST_CONTRACT_REJECTED']);
const outcomes=new Set(['SUCCESS','HTTP_FAILURE','BUSINESS_FAILURE','RESPONSE_FAILURE','PENDING','TRANSPORT_FAILURE']);
const number=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0&&value<=1e9?Math.round(value*1000)/1000:null;
const flag=value=>value===true;
// Construct a new allowlisted document: never recursively redact arbitrary input.
export function sanitizedCombinedReport(input) {
  return {schemaVersion:1,stage:'STEP_7A_MOCK_RUNNER',evidenceScope:'SYNTHETIC_MOCK_ONLY_NOT_EPS_BANK_EVIDENCE',
    diagnosticAttemptId:/^[a-f0-9-]{36}$/.test(input.attemptId??'')?input.attemptId:null,
    outcome:['MOCK_SUCCESS','PAUSED','FAILED','STATUS_UNCONFIRMED'].includes(input.outcome)?input.outcome:'FAILED',
    steps:input.steps.filter(s=>['AUTH','INITIALIZE','STATUS'].includes(s.name)).map(s=>({name:s.name,
      httpStatus:Number.isInteger(s.httpStatus)&&s.httpStatus>=100&&s.httpStatus<=599?s.httpStatus:null,
      outcome:outcomes.has(s.outcome)?s.outcome:'RESPONSE_FAILURE',code:codes.has(s.code)?s.code:'DIAGNOSTIC_REJECTED',
      paymentVerified:flag(s.paymentVerified),timing:{source:s.timing?.source==='local-tls-measurement'?'local-tls-measurement':'in-memory-simulation',
        dnsPerformed:false,dnsReason:'NUMERIC_LOOPBACK_OR_IN_MEMORY_NO_DNS',tcpConnectMs:number(s.timing?.tcpConnectMs),
        tlsHandshakeMs:number(s.timing?.tlsHandshakeMs),firstByteMs:number(s.timing?.firstByteMs),totalMs:number(s.timing?.totalMs),
        tlsVerified:s.timing?.tlsVerified===null?null:flag(s.timing?.tlsVerified)}})),
    events:input.events.filter(e=>['ATTEMPT_RESERVED','INITIALIZE_DURABLY_CLAIMED','HOSTED_PAYMENT_PAUSED',
      'HOSTED_COMPLETION_EXPLICITLY_SIMULATED','STATUS_DURABLY_CLAIMED','RESUMED_WITHOUT_AUTH_OR_INITIALIZE'].includes(e)),
    hostedPayment:{realHostedPageOpened:false,callbackSent:false,simulationOnly:true},
    capture:input.capture?{file:'session.pcapng',format:'pcapng',interface:'NpcapLoopback-only',
      readinessBeforeRequests:true,packetCount:number(input.capture.packetCount),tcpStreamCount:number(input.capture.tcpStreamCount),
      tlsRecordPackets:number(input.capture.tlsRecordPackets),timestampsValid:flag(input.capture.timestampsValid),
      loopbackOnly:flag(input.capture.loopbackOnly),sensitivePlaintextFound:flag(input.capture.sensitivePlaintextFound)}:null,
    safety:{realEpsRequestsSent:0,realCredentialsRead:false,callbacksTriggered:false,databaseAccess:false,
      tlsKeyLoggingEnabled:false,rawSensitivePayloadRecording:false,automaticRetries:0,
      mockLedgerOnly:true,timingDoesNotMeasureEps:true},
    ...executionSafetySummary(),liveExecutionDecision:'NO_GO'};
}
export function writeCombinedReport(directory,input) {
  const report=sanitizedCombinedReport(input);
  writeExclusive(path.join(directory,'combined-report.json'),JSON.stringify(report,null,2)+'\n');
  return report;
}
export async function captureMockExchange(handle,cfg,directory,flow) {
  const info=mockTransportInfo(handle);
  if(info.kind!=='loopback-tls'||!Number.isInteger(info.port))throw Error('MOCK_CAPTURE_REQUIRES_OWNED_TLS_LISTENER');
  const startedAt=Date.now();
  await runCaptureProbe({kind:'loopback',port:info.port,tsharkPath:cfg.capture.tsharkPath,outputDirectory:directory},flow);
  const completedAt=Date.now(),file=path.join(directory,'session.pcapng');
  const read=spawnSync(cfg.capture.tsharkPath,['-n','-r',file,'-T','fields','-E','separator=|',
    '-e','frame.time_epoch','-e','ip.src','-e','ip.dst','-e','tcp.srcport','-e','tcp.dstport','-e','tcp.stream','-e','tls.record.content_type'],
    {env:localToolEnvironment(),encoding:'utf8',windowsHide:true,shell:false,timeout:5000,maxBuffer:1024*1024});
  if(read.error||read.status!==0)throw Error('MOCK_PCAP_UNREADABLE');
  const lines=read.stdout.trim().split(/\r?\n/).filter(Boolean),streams=new Set();let tlsRecordPackets=0,previous=-Infinity;
  for(const line of lines){
    const [stamp,source,destination,sourcePort,destinationPort,stream,tlsRecord]=line.split('|');
    const time=Number(stamp)*1000;
    if(source!=='127.0.0.1'||destination!=='127.0.0.1'||![Number(sourcePort),Number(destinationPort)].includes(info.port)||
      !/^\d+$/.test(stream)||!Number.isFinite(time)||time<startedAt-2000||time>completedAt+2000||time<previous)throw Error('MOCK_PCAP_SCOPE_OR_TIME_INVALID');
    previous=time;streams.add(stream);if(tlsRecord)tlsRecordPackets++;
  }
  if(!lines.length||!streams.size||!tlsRecordPackets)throw Error('MOCK_PCAP_TRAFFIC_MISSING');
  const bytes=fs.readFileSync(file);
  const sensitivePlaintextFound=['SYNTHETIC_EPS_PASSWORD','SYNTHETIC_UTF8_HASH_KEY','SYNTHETIC_OPAQUE_AUTH_TOKEN',
    'EPS Diagnostic Synthetic Customer','eps-diagnostic@example.com'].some(value=>bytes.includes(Buffer.from(value)));
  if(sensitivePlaintextFound)throw Error('MOCK_PCAP_PLAINTEXT_FOUND');
  return {packetCount:lines.length,tcpStreamCount:streams.size,tlsRecordPackets,timestampsValid:true,loopbackOnly:true,sensitivePlaintextFound:false};
}
