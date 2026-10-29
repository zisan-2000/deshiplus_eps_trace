import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

export const LOOPBACK_INTERFACE = '\\Device\\NPF_Loopback';
// No complete Ethernet/Wi-Fi frame can pass this length filter. Never use the
// planned EPS filter for a Wi-Fi permission probe: it could collect live traffic.
export const WIFI_PERMISSION_FILTER = 'less 1';

export function localProbePlan(kind, port) {
  if (kind === 'wifi-permission') return { interface: '5', filter: WIFI_PERMISSION_FILTER, durationSeconds: 2 };
  if (kind !== 'loopback' || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('LOCAL_PROBE_PLAN_INVALID');
  return { interface: LOOPBACK_INTERFACE,
    filter: `ip and tcp and src host 127.0.0.1 and dst host 127.0.0.1 and port ${port}`, durationSeconds: 3 };
}

export function hasPcapngInterface(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const bytes = Buffer.alloc(65536), length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (length < 28 || bytes.readUInt32LE(0) !== 0x0a0d0d0a) return false;
    const little = bytes.readUInt32LE(8) === 0x1a2b3c4d;
    if (!little && bytes.readUInt32BE(8) !== 0x1a2b3c4d) return false;
    const read = offset => little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
    let offset = 0;
    while (offset + 12 <= length) {
      const blockLength = read(offset + 4);
      if (blockLength < 12 || blockLength % 4 || offset + blockLength > length || read(offset + blockLength - 4) !== blockLength) return false;
      if (read(offset) === 1 && blockLength >= 20) return true;
      offset += blockLength;
    }
    return false;
  } catch { return false; }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}

export function localToolEnvironment(source = process.env) {
  const allowed = new Set(['path', 'pathext', 'systemroot', 'windir', 'comspec', 'temp', 'tmp',
    'programfiles', 'programfiles(x86)', 'programw6432', 'psmodulepath']);
  const env = {};
  for (const [key, value] of Object.entries(source)) if (allowed.has(key.toLowerCase())) env[key] = value;
  return env;
}
async function within(promise, ms) {
  let timer;
  try { return await Promise.race([promise, new Promise(resolve => { timer = setTimeout(() => resolve(false), ms); })]); }
  finally { clearTimeout(timer); }
}
async function terminateOwned(child, exit) {
  if (process.platform === 'win32' && Number.isInteger(child.pid) && child.pid > 0) {
    spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore', timeout: 3000 });
  } else child.kill('SIGTERM');
  if (!await within(exit, 1500)) {
    child.kill('SIGKILL');
    if (!await within(exit, 1500)) throw new Error('LOCAL_CAPTURE_CLEANUP_FAILED');
  }
}

// Bounded local probes only. This cannot select an EPS host/filter or initiate an API call.
export async function runCaptureProbe({ kind, port, tsharkPath, outputDirectory }, onReady = async () => {},
  { spawnProcess = spawn, readinessTimeoutMs = 8000 } = {}) {
  const plan = localProbePlan(kind, port);
  const pcap = path.join(outputDirectory, kind === 'loopback' ? 'session.pcapng' : 'wifi-permission.pcapng');
  if (fs.existsSync(pcap)) throw new Error('LOCAL_CAPTURE_OUTPUT_ALREADY_EXISTS');
  const events = [];
  const args = ['-n', '-i', plan.interface, '-f', plan.filter, '-a', `duration:${plan.durationSeconds}`,
    '-F', 'pcapng', '--update-interval', '20', '-w', pcap, '-q'];
  const child = spawnProcess(tsharkPath, args, { windowsHide: true, shell: false,
    env: localToolEnvironment(), stdio: ['ignore', 'ignore', 'pipe'] });
  let spawned = false, banner = false, closed = false, launchError = false, exitCode = null, stderr = '';
  let resolveExit;
  const exited = new Promise(resolve => { resolveExit = resolve; });
  child.once('spawn', () => { spawned = true; });
  child.once('error', () => { launchError = true; closed = true; resolveExit(true); });
  child.once('close', code => { closed = true; exitCode = code; resolveExit(true); });
  child.stderr?.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-8192); banner ||= /Capturing on\s/.test(stderr); });
  try {
    const deadline = Date.now() + readinessTimeoutMs;
    let ready = false;
    while (Date.now() < deadline) {
      if (launchError || closed) throw new Error('LOCAL_CAPTURE_EXITED_BEFORE_READY');
      if (spawned && banner && hasPcapngInterface(pcap)) { ready = true; break; }
      await delay(20);
    }
    if (!ready) throw new Error('LOCAL_CAPTURE_READINESS_TIMEOUT');
    const readyAt = new Date().toISOString(); events.push('CAPTURE_READY');
    await onReady();
    if (!await within(exited, (plan.durationSeconds + 4) * 1000)) throw new Error('LOCAL_CAPTURE_STOP_TIMEOUT');
    if (exitCode !== 0 || !hasPcapngInterface(pcap)) throw new Error('LOCAL_CAPTURE_EXIT_OR_FORMAT_FAILED');
    events.push('CAPTURE_STOPPED');
    return { kind, ready: true, readyAt, completedAt: new Date().toISOString(),
      interface: plan.interface, filter: plan.filter, pcapFile: path.basename(pcap), pcapBytes: fs.statSync(pcap).size,
      format: 'pcapng', exitCode, events };
  } finally {
    if (!closed) await terminateOwned(child, exited);
  }
}
