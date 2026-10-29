import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { hasPcapngInterface, localToolEnvironment } from './capture-readiness.mjs';
import { assertLiveExecutionCapability } from './live-execution-gate.mjs';

export const LIVE_CAPTURE_PLAN = Object.freeze({
  interface: '5', filter: 'tcp port 443 and host sandboxpgapi.eps.com.bd', format: 'pcapng',
  fileName: 'session.pcapng', preserve: true, tlsKeyLogging: false, rawPayloadReport: false
});

export function validateLiveCaptureConfig(config) {
  const c = config?.capture;
  return !!c && c.interface === LIVE_CAPTURE_PLAN.interface && c.captureFilter === LIVE_CAPTURE_PLAN.filter &&
    c.format === 'pcapng' && c.fileName === 'session.pcapng' && c.preservePcap === true &&
    c.readinessRequired === true && c.abortOnFailure === true && c.tlsKeyLoggingEnabled === false;
}

export async function withLiveCapture(capability, config, directory, flow, dependencies = {}) {
  assertLiveExecutionCapability(capability);
  if (!validateLiveCaptureConfig(config)) throw Error('LIVE_CAPTURE_CONFIGURATION_REJECTED');
  const pcap = path.join(directory, LIVE_CAPTURE_PLAN.fileName);
  if (fs.existsSync(pcap)) throw Error('LIVE_CAPTURE_OUTPUT_ALREADY_EXISTS');
  const spawnProcess = dependencies.spawnProcess ?? spawn;
  const child = spawnProcess(config.capture.tsharkPath,
    ['-n','-i','5','-f',LIVE_CAPTURE_PLAN.filter,'-F','pcapng','--update-interval','20','-w',pcap,'-q'],
    { windowsHide:true, shell:false, env:localToolEnvironment(), stdio:['ignore','ignore','pipe'] });
  let banner=false, closed=false, launchError=false, stderr='';
  child.once('error',()=>{launchError=true;closed=true;}); child.once('close',()=>{closed=true;});
  child.stderr?.on('data',chunk=>{stderr=(stderr+chunk.toString()).slice(-8192);banner||=/Capturing on\s/.test(stderr);});
  try {
    const deadline=Date.now()+config.capture.readinessTimeoutMs;
    while(Date.now()<deadline) {
      if(launchError||closed)throw Error('LIVE_CAPTURE_EXITED_BEFORE_READY');
      if(banner&&hasPcapngInterface(pcap))return await flow({ready:true,pcap});
      await delay(20);
    }
    throw Error('LIVE_CAPTURE_READINESS_TIMEOUT');
  } finally {
    if(!closed)child.kill('SIGTERM');
  }
}
