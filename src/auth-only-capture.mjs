import fs from 'node:fs';
import path from 'node:path';
import { hasPcapngInterface } from './capture-readiness.mjs';

export const AUTH_CAPTURE_PLAN=Object.freeze({interface:'5',filter:'tcp port 443 and host sandboxpgapi.eps.com.bd',format:'pcapng',fileName:'session.pcapng',durationSeconds:25});
export const AUTH_CAPTURE_OWNER='POWERSHELL_TSHARK_V1';

export function assertAuthCaptureConfig(cfg) {
  const c=cfg?.capture;
  if(!c||c.interface!=='5'||c.captureFilter!==AUTH_CAPTURE_PLAN.filter||c.fileName!=='session.pcapng'||c.format!=='pcapng'||
    c.preservePcap!==true||c.readinessRequired!==true||c.abortOnFailure!==true||c.tlsKeyLoggingEnabled!==false)throw Error('AUTH_CAPTURE_CONFIGURATION_REJECTED');
  return true;
}

function externalCaptureContext(directory,environment) {
  if(environment.EPS_AUTH_CAPTURE_OWNER!==AUTH_CAPTURE_OWNER)throw Error('AUTH_CAPTURE_POWERSHELL_OWNER_REQUIRED');
  if(environment.EPS_AUTH_CAPTURE_INTERFACE!==AUTH_CAPTURE_PLAN.interface||
    environment.EPS_AUTH_CAPTURE_FILTER!==AUTH_CAPTURE_PLAN.filter)throw Error('AUTH_CAPTURE_CONTEXT_INVALID');
  const expectedDirectory=path.resolve(directory);
  if(path.resolve(environment.EPS_AUTH_CAPTURE_DIRECTORY??'')!==expectedDirectory)throw Error('AUTH_CAPTURE_CONTEXT_INVALID');
  const readyAt=new Date(environment.EPS_AUTH_CAPTURE_READY_AT??'');
  if(!Number.isFinite(readyAt.getTime())||Math.abs(Date.now()-readyAt.getTime())>5*60*1000)throw Error('AUTH_CAPTURE_CONTEXT_INVALID');
  const pcap=path.join(expectedDirectory,AUTH_CAPTURE_PLAN.fileName);
  if(!hasPcapngInterface(pcap))throw Error('AUTH_CAPTURE_NOT_READY');
  return {pcap,readyAt:readyAt.toISOString()};
}

// TShark is deliberately not launched here. The PowerShell AUTH wrapper owns
// interface inventory, capture launch, the readiness gate and final PCAP read.
export async function captureAuthOnly(cfg,directory,flow,{environment=process.env}={}) {
  assertAuthCaptureConfig(cfg);
  const context=externalCaptureContext(directory,environment);
  const capture={ready:true,readyAt:context.readyAt,interface:AUTH_CAPTURE_PLAN.interface,filter:AUTH_CAPTURE_PLAN.filter,
    file:AUTH_CAPTURE_PLAN.fileName,format:AUTH_CAPTURE_PLAN.format,bytes:fs.statSync(context.pcap).size,packetCount:null};
  try {
    const value=await flow();
    capture.bytes=fs.statSync(context.pcap).size;
    return {value,capture};
  } catch(error) {
    if(error&&typeof error==='object')error.capture=capture;
    throw error;
  }
}
