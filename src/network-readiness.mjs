// Explicit readiness diagnostics: one fixed-host DNS lookup, local tools and
// payload-free loopback TCP only. No HTTP/TLS/payment client exists here.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ENDPOINTS, STAGE } from './eps-contract.mjs';
import { runCaptureProbe, localToolEnvironment } from './capture-readiness.mjs';

const projectRoot = fileURLToPath(new URL('../', import.meta.url));
export const EPS_HOSTNAME = 'sandboxpgapi.eps.com.bd';
export const INTENDED_EPS_FILTER = 'tcp port 443 and host ' + EPS_HOSTNAME;
function tool(file, args, { timeout = 10000, env = localToolEnvironment() } = {}) {
  const result = spawnSync(file, args, { encoding: 'utf8', windowsHide: true, shell: false,
    timeout, maxBuffer: 1024 * 1024, env, stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error || result.status !== 0) throw new Error('LOCAL_TOOL_EXECUTION_FAILED');
  return result.stdout;
}
const version = text => (text.match(/\b\d+\.\d+(?:\.\d+)?\b/) || [])[0] || null;
export const parseNpcapRuntimeVersion = text => text.match(/Npcap(?: version)?\s+([\d.]+)/i)?.[1] || null;
export function parseInterfaces(text) {
  return text.split(/\r?\n/).map(line => {
    const match = /^(\d+)\.\s+(\S+)\s+\((.*)\)\s*$/.exec(line);
    return match ? { index: Number(match[1]), device: match[2], name: match[3] } : null;
  }).filter(Boolean);
}
const guid = value => String(value || '').replace(/[{}]/g, '').toLowerCase();
export function identifyWifi5(interfaces, adapters) {
  const item = interfaces.find(i => i.index === 5);
  const match = /\\Device\\NPF_\{([0-9a-f-]{36})\}/i.exec(item?.device || '');
  const adapter = match && adapters.find(a => guid(a.InterfaceGuid) === guid(match[1]));
  return { available: !!item, guidMatched: !!adapter,
    wifiIdentified: !!adapter && /^wi-fi$/i.test(item.name) && /wi-fi|wireless/i.test(adapter.Name + ' ' + adapter.InterfaceDescription),
    up: !!adapter && adapter.Status === 'Up', name: adapter?.Name || null,
    description: adapter?.InterfaceDescription || null };
}
export function assertDiagnosticSafety(cfg, environment = process.env) {
  if (cfg.execution.networkEnabled !== false || cfg.execution.paymentRequestsEnabled !== false ||
      cfg.execution.callbacksEnabled !== false || cfg.execution.automaticRetries !== 0 ||
      cfg.network.rejectUnauthorized !== true || cfg.network.followRedirects !== false || cfg.capture.enabled !== false ||
      cfg.capture.interface !== '5' || cfg.capture.tlsKeyLoggingEnabled !== false ||
      ['includeRequestHeaders', 'includeResponseHeaders', 'includeRequestBody', 'includeResponseBody'].some(k => cfg.evidence[k] !== false)) {
    throw new Error('READINESS_SAFETY_CONFIGURATION_REQUIRED');
  }
  if (environment.SSLKEYLOGFILE || /--tls-keylog(?:=|\s|$)/i.test(environment.NODE_OPTIONS || '') ||
      environment.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('READINESS_UNSAFE_TLS_ENVIRONMENT');
  if (Object.values(ENDPOINTS).some(value => new URL(value).protocol !== 'https:' || new URL(value).hostname !== EPS_HOSTNAME) ||
      cfg.capture.captureFilter !== INTENDED_EPS_FILTER) throw new Error('READINESS_DESTINATION_PLAN_INVALID');
}
export function getInterfaces(tsharkPath) { return parseInterfaces(tool(tsharkPath, ['-D'])); }

function inventory(cfg) {
  const tsharkText = tool(cfg.capture.tsharkPath, ['--version']);
  const dumpcapPath = path.join(path.dirname(cfg.capture.tsharkPath), 'dumpcap.exe');
  const dumpcapText = tool(dumpcapPath, ['--version']);
  const interfaces = getInterfaces(cfg.capture.tsharkPath);
  const powershell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
  let windows;
  try { windows = JSON.parse(tool(powershell, ['-NoProfile', '-NonInteractive', '-File',
    path.join(projectRoot, 'scripts/Get-LocalCaptureEnvironment.ps1')], { timeout: 15000 })); }
  catch { throw new Error('LOCAL_CAPTURE_ENVIRONMENT_INSPECTION_FAILED'); }
  const adapters = Array.isArray(windows.adapters) ? windows.adapters : [windows.adapters].filter(Boolean);
  let npmVersion = version((process.env.npm_config_user_agent || '').match(/npm\/([\d.]+)/)?.[1] || '');
  if (!npmVersion) {
    const npmCli = path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
    npmVersion = version(tool(process.execPath, [npmCli, '--version'], { env: {
      ...localToolEnvironment(), npm_config_cache: path.join(projectRoot, '.tools/npm-cache'),
      npm_config_logs_max: '0', npm_config_update_notifier: 'false', npm_config_offline: 'true' } }));
  }
  return { node: process.version, npm: npmVersion, tshark: version(tsharkText), dumpcap: version(dumpcapText),
    npcap: { driverVersion: windows.npcapVersion || null,
      runtimeVersion: parseNpcapRuntimeVersion(tsharkText),
      running: windows.npcapRunning === true, adminOnly: [0, 1].includes(windows.npcapAdminOnly) ? windows.npcapAdminOnly : null },
    processElevated: windows.processElevated === true, interfaces,
    wifi5: identifyWifi5(interfaces, adapters) };
}
async function boundedLookup(resolveHost) {
  let timer;
  try {
    return await Promise.race([resolveHost(EPS_HOSTNAME, { all: true, verbatim: true }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('EPS_DNS_LOOKUP_TIMEOUT')), 6000); })]);
  } finally { clearTimeout(timer); }
}
export async function checkHostnameAndFilter(tsharkPath, { resolveHost = lookup, compile = tool } = {}) {
  let records;
  try { records = await boundedLookup(resolveHost); }
  catch { return { hostname: EPS_HOSTNAME, dnsResolved: false, dnsAddressCount: 0, filterCompiled: false, code: 'EPS_DNS_LOOKUP_FAILED' }; }
  if (!Array.isArray(records) || !records.length || records.some(r => !net.isIP(r.address) || ![4, 6].includes(r.family))) {
    return { hostname: EPS_HOSTNAME, dnsResolved: false, dnsAddressCount: 0, filterCompiled: false, code: 'EPS_DNS_RESULT_INVALID' };
  }
  try {
    const bpf = compile(path.join(path.dirname(tsharkPath), 'dumpcap.exe'), ['-i', '5', '-f', INTENDED_EPS_FILTER, '-d']);
    if (!bpf.trim()) throw new Error();
    return { hostname: EPS_HOSTNAME, dnsResolved: true, dnsAddressCount: records.length,
      addressFamilies: [...new Set(records.map(r => r.family))], filter: INTENDED_EPS_FILTER,
      filterCompiled: true, apiConnectionAttempted: false };
  } catch { return { hostname: EPS_HOSTNAME, dnsResolved: true, dnsAddressCount: records.length,
    filterCompiled: false, code: 'EPS_FILTER_COMPILE_FAILED' }; }
}

export function analyzeLocalFrames(text, { port, startedAt, completedAt, requirePackets }) {
  const lines = text.split(/\r?\n/).filter(line => line.trim());
  if (!requirePackets) {
    if (lines.length) throw new Error('WIFI_PERMISSION_PROBE_COLLECTED_PACKETS');
    return { readable: true, packetCount: 0, unrelatedWifiTrafficCaptured: false };
  }
  if (!lines.length) throw new Error('LOOPBACK_PACKETS_MISSING');
  const streams = new Set(), times = []; let previous = -Infinity, clientToServerPackets = 0, serverToClientPackets = 0;
  for (const line of lines) {
    const [timeText, source, destination, sourcePort, destinationPort, payloadBytes, stream] = line.split('|');
    const time = Number(timeText);
    if (!Number.isFinite(time) || time < Date.parse(startedAt) / 1000 - 2 || time > Date.parse(completedAt) / 1000 + 2 || time < previous) throw new Error('PCAP_TIMESTAMP_VALIDATION_FAILED');
    if (source !== '127.0.0.1' || destination !== '127.0.0.1' ||
        ![Number(sourcePort), Number(destinationPort)].includes(port) || payloadBytes !== '0' || !/^\d+$/.test(stream)) {
      throw new Error('PCAP_NOT_SYNTHETIC_LOOPBACK_ONLY');
    }
    if (Number(destinationPort) === port) clientToServerPackets++; else serverToClientPackets++;
    previous = time; times.push(time); streams.add(stream);
  }
  if (streams.size !== 3) throw new Error('LOOPBACK_STREAM_COUNT_MISMATCH');
  return { readable: true, packetCount: lines.length, tcpStreamCount: streams.size, clientToServerPackets, serverToClientPackets,
    firstPacketUtc: new Date(times[0] * 1000).toISOString(), lastPacketUtc: new Date(times.at(-1) * 1000).toISOString(),
    timestampsValid: true, timestampsMonotonic: true, applicationPayloadBytes: 0, loopbackOnly: true };
}
function readFrames(tsharkPath, file) {
  return tool(tsharkPath, ['-n', '-r', file, '-T', 'fields', '-E', 'separator=|',
    '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport',
    '-e', 'tcp.dstport', '-e', 'tcp.len', '-e', 'tcp.stream']);
}
async function syntheticConnections(port) {
  for (let i = 0; i < 3; i++) await new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.setTimeout(2000, () => socket.destroy(new Error('LOCAL_TCP_TIMEOUT')));
    socket.once('error', () => reject(new Error('LOCAL_TCP_SMOKE_FAILED')));
    socket.once('close', () => resolve());
  });
}
function safeCode(error) {
  return /^(LOCAL_|LOOPBACK_|PCAP_|WIFI_|READINESS_)[A-Z0-9_]+$/.test(error?.message || '') ? error.message : 'READINESS_CHECK_FAILED';
}

export async function runReadiness(cfg, { localOnly = false } = {}) {
  assertDiagnosticSafety(cfg);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.join(projectRoot, 'evidence/readiness', stamp + '_' + randomUUID().slice(0, 8));
  fs.mkdirSync(dir, { recursive: true });
  const report = { stage: STAGE, startedAt: new Date().toISOString(), completedAt: null,
    outcome: 'FAIL', errors: [], tools: null, hostnameCheck: null, capture: {},
    safety: { epsApiRequestsSent: 0, databaseAccess: false, callbacksTriggered: false,
      tlsKeyLoggingEnabled: false, rawSensitivePayloadRecording: false, localSyntheticTrafficOnly: true },
    limitations: ['DNS/filter compilation does not test EPS TCP, TLS, authentication or payment availability.',
      'Wi-Fi permission capture accepts no complete Ethernet frames; it does not demonstrate live Wi-Fi packet delivery.',
      'session.pcapng contains only payload-free synthetic loopback TCP, not EPS evidence.'] };
  let server;
  try {
    report.tools = inventory(cfg);
    const wifi = report.tools.wifi5;
    if (!wifi.available || !wifi.guidMatched || !wifi.wifiIdentified || !wifi.up) throw new Error('WIFI_INTERFACE_5_IDENTITY_NOT_READY');
    if (Number(process.versions.node.split('.')[0]) < 20 || !report.tools.npm || !report.tools.tshark || !report.tools.dumpcap || !report.tools.npcap.driverVersion || !report.tools.npcap.running) throw new Error('LOCAL_CAPTURE_TOOLCHAIN_NOT_READY');
    report.hostnameCheck = localOnly ? { hostname: EPS_HOSTNAME, checked: false, code: 'LOCAL_ONLY_DNS_NOT_REQUESTED' }
      : await checkHostnameAndFilter(cfg.capture.tsharkPath);
    const wifiCapture = await runCaptureProbe({ kind: 'wifi-permission', tsharkPath: cfg.capture.tsharkPath, outputDirectory: dir });
    report.capture.wifiPermission = { ...wifiCapture, ...analyzeLocalFrames(readFrames(cfg.capture.tsharkPath,
      path.join(dir, wifiCapture.pcapFile)), { requirePackets: false }) };
    server = net.createServer(socket => { socket.on('error', () => socket.destroy()); socket.end(); });
    await new Promise((resolve, reject) => { server.once('error', () => reject(new Error('LOCAL_TCP_LISTEN_FAILED'))); server.listen(0, '127.0.0.1', resolve); });
    const port = server.address().port;
    const loopbackCapture = await runCaptureProbe({ kind: 'loopback', port, tsharkPath: cfg.capture.tsharkPath, outputDirectory: dir }, () => syntheticConnections(port));
    report.capture.loopback = { ...loopbackCapture, ...analyzeLocalFrames(readFrames(cfg.capture.tsharkPath,
      path.join(dir, loopbackCapture.pcapFile)), { port, startedAt: report.startedAt, completedAt: loopbackCapture.completedAt, requirePackets: true }) };
    if (fs.readdirSync(dir).some(name => /keylog|\.keys(?:\.|$)/i.test(name))) throw new Error('LOCAL_TLS_KEY_ARTIFACT_FORBIDDEN');
    report.safety.tlsKeyFilesCreated = false;
    if (!localOnly && (!report.hostnameCheck.dnsResolved || !report.hostnameCheck.filterCompiled)) report.errors.push(report.hostnameCheck.code);
    report.outcome = report.errors.length ? 'FAIL' : 'PASS';
  } catch (error) { report.errors.push(safeCode(error)); }
  finally {
    if (server) await new Promise(resolve => server.close(() => resolve()));
    report.completedAt = new Date().toISOString();
    fs.writeFileSync(path.join(dir, 'readiness-report.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  }
  return { report, reportPath: path.join(dir, 'readiness-report.json'), pcapPath: report.capture.loopback ? path.join(dir, 'session.pcapng') : null };
}
