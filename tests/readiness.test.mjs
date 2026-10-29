import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';
import { createTemplate } from '../src/eps-contract.mjs';
import { localProbePlan, WIFI_PERMISSION_FILTER, LOOPBACK_INTERFACE, hasPcapngInterface,
  localToolEnvironment, runCaptureProbe } from '../src/capture-readiness.mjs';
import { parseInterfaces, identifyWifi5, assertDiagnosticSafety, EPS_HOSTNAME, INTENDED_EPS_FILTER,
  checkHostnameAndFilter, analyzeLocalFrames, parseNpcapRuntimeVersion } from '../src/network-readiness.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
function temporary(t) {
  const parent = path.join(root, 'tmp'); fs.mkdirSync(parent, { recursive: true });
  const dir = fs.mkdtempSync(path.join(parent, 'readiness-test-'));
  t.after(() => {
    for (const name of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, name));
    fs.rmdirSync(dir); if (fs.readdirSync(parent).length === 0) fs.rmdirSync(parent);
  });
  return dir;
}
function header(little = true) {
  const b = Buffer.alloc(48), write = (value, at) => little ? b.writeUInt32LE(value, at) : b.writeUInt32BE(value, at);
  write(0x0a0d0d0a, 0); write(28, 4); write(0x1a2b3c4d, 8); write(1, 12); write(0xffffffff, 16); write(0xffffffff, 20); write(28, 24);
  write(1, 28); write(20, 32); write(1, 36); write(65535, 40); write(20, 44);
  return b;
}
function fakeCapture(mode, inspect = () => {}) {
  return (_file, args, options) => {
    inspect(args, options);
    const child = new EventEmitter(); child.stderr = new EventEmitter();
    const file = args[args.indexOf('-w') + 1]; const timers = [];
    child.kill = () => { for (const timer of timers) clearTimeout(timer); queueMicrotask(() => child.emit('close', 1)); return true; };
    queueMicrotask(() => child.emit('spawn'));
    timers.push(setTimeout(() => {
      if (mode === 'error') { child.emit('error', new Error('SYNTHETIC_PRIVATE_PROCESS_ERROR')); return; }
      if (mode !== 'no-file') fs.writeFileSync(file, mode === 'partial' ? header().subarray(0, 36) : header());
      if (mode !== 'no-banner') child.stderr.emit('data', Buffer.from('Capturing on SYNTHETIC\n'));
    }, 5));
    if (mode !== 'no-file') timers.push(setTimeout(() => child.emit('close', mode === 'bad-exit' ? 1 : 0), 90));
    return child;
  };
}

test('permission probe cannot select an EPS or ambient Wi-Fi filter', () => {
  assert.deepEqual(localProbePlan('wifi-permission'), { interface: '5', filter: WIFI_PERMISSION_FILTER, durationSeconds: 2 });
  assert.equal(WIFI_PERMISSION_FILTER, 'less 1');
  const loopback = localProbePlan('loopback', 54321);
  assert.equal(loopback.interface, LOOPBACK_INTERFACE);
  assert.match(loopback.filter, /src host 127\.0\.0\.1 and dst host 127\.0\.0\.1 and port 54321$/);
  assert.throws(() => localProbePlan('eps', 443), /LOCAL_PROBE_PLAN_INVALID/);
  for (const port of [0, -1, 65536, '443', null]) assert.throws(() => localProbePlan('loopback', port), /LOCAL_PROBE_PLAN_INVALID/);
});
test('external tools receive no credential, database or TLS-key environment values', () => {
  const env = localToolEnvironment({ Path: 'synthetic-path', SystemRoot: 'synthetic-root', TEMP: 'synthetic-temp',
    EPS_PASSWORD: 'SYNTHETIC_PRIVATE_PASSWORD', EPS_HASH_KEY: 'SYNTHETIC_PRIVATE_KEY', DATABASE_URL: 'SYNTHETIC_DATABASE',
    AUTH_SECRET: 'SYNTHETIC_SECRET', SSLKEYLOGFILE: 'synthetic-keys', NODE_OPTIONS: '--tls-keylog=synthetic' });
  assert.deepEqual(Object.keys(env).sort(), ['Path', 'SystemRoot', 'TEMP']);
  assert.ok(!JSON.stringify(env).includes('PRIVATE'));
});
test('Npcap runtime version parsing supports both TShark version formats', () => {
  assert.equal(parseNpcapRuntimeVersion('  +Npcap 1.90, libpcap 1.10.7'), '1.90');
  assert.equal(parseNpcapRuntimeVersion('with Npcap version 1.90, based on libpcap'), '1.90');
  assert.equal(parseNpcapRuntimeVersion('no runtime version'), null);
});
for (const little of [true, false]) test('PCAPNG requires complete section and interface blocks, endian ' + little, t => {
  const dir = temporary(t), file = path.join(dir, 'probe.pcapng'); fs.writeFileSync(file, header(little));
  assert.equal(hasPcapngInterface(file), true);
});
for (const [label, mutate] of [
  ['empty', () => Buffer.alloc(0)], ['section only', b => b.subarray(0, 28)],
  ['partial interface', b => b.subarray(0, 47)], ['wrong trailer', b => { b.writeUInt32LE(24, 44); return b; }],
  ['bad byte order', b => { b.writeUInt32LE(0, 8); return b; }], ['unaligned block', b => { b.writeUInt32LE(27, 4); return b; }]
]) test('PCAPNG rejects ' + label, t => {
  const dir = temporary(t), file = path.join(dir, 'probe.pcapng'); fs.writeFileSync(file, mutate(header()));
  assert.equal(hasPcapngInterface(file), false);
});
test('local capture readiness gates traffic on banner AND complete PCAPNG header', async t => {
  const dir = temporary(t); let called = 0;
  const result = await runCaptureProbe({ kind: 'wifi-permission', tsharkPath: 'synthetic-tool', outputDirectory: dir }, async () => {
    assert.equal(hasPcapngInterface(path.join(dir, 'wifi-permission.pcapng')), true); called++;
  }, { spawnProcess: fakeCapture('ready', (args, options) => {
    assert.equal(args[args.indexOf('-f') + 1], 'less 1');
    assert.equal(args[args.indexOf('-F') + 1], 'pcapng'); assert.ok(args.includes('-n'));
    assert.equal(options.shell, false); assert.equal(options.windowsHide, true);
    assert.equal(options.env.SSLKEYLOGFILE, undefined); assert.equal(options.env.EPS_PASSWORD, undefined);
  }), readinessTimeoutMs: 200 });
  assert.equal(called, 1); assert.equal(result.ready, true); assert.equal(result.exitCode, 0);
  assert.deepEqual(result.events, ['CAPTURE_READY', 'CAPTURE_STOPPED']);
  assert.ok(fs.existsSync(path.join(dir, result.pcapFile)));
});
for (const mode of ['error', 'partial', 'no-banner', 'no-file']) test('capture ' + mode + ' blocks the traffic callback', async t => {
  const dir = temporary(t); let called = false;
  await assert.rejects(runCaptureProbe({ kind: 'wifi-permission', tsharkPath: 'synthetic-tool', outputDirectory: dir }, async () => { called = true; },
    { spawnProcess: fakeCapture(mode), readinessTimeoutMs: 120 }), /LOCAL_CAPTURE_/);
  assert.equal(called, false);
});
test('capture nonzero exit is not successful readiness evidence', async t => {
  const dir = temporary(t);
  await assert.rejects(runCaptureProbe({ kind: 'loopback', port: 54321, tsharkPath: 'synthetic-tool', outputDirectory: dir }, async () => {},
    { spawnProcess: fakeCapture('bad-exit'), readinessTimeoutMs: 200 }), /LOCAL_CAPTURE_EXIT_OR_FORMAT_FAILED/);
});
test('a capture probe never overwrites an existing PCAP', async t => {
  const dir = temporary(t); fs.writeFileSync(path.join(dir, 'session.pcapng'), header());
  await assert.rejects(runCaptureProbe({ kind: 'loopback', port: 54321, tsharkPath: 'synthetic-tool', outputDirectory: dir }), /LOCAL_CAPTURE_OUTPUT_ALREADY_EXISTS/);
});

const syntheticGuid = '11111111-2222-3333-4444-555555555555';
const listing = `warning ignored\n5. \\Device\\NPF_{${syntheticGuid}} (Wi-Fi)\n8. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n`;
const adapters = [{ Name: 'Wi-Fi', InterfaceDescription: 'Synthetic Wireless adapter', InterfaceGuid: '{' + syntheticGuid + '}', Status: 'Up' }];
test('Interface 5 is identified by matching GUID, Wi-Fi identity and Up state', () => {
  const parsed = parseInterfaces(listing); assert.equal(parsed.length, 2);
  const wifi = identifyWifi5(parsed, adapters);
  assert.equal(wifi.available && wifi.guidMatched && wifi.wifiIdentified && wifi.up, true);
  assert.equal(identifyWifi5(parsed, []).guidMatched, false);
  assert.equal(identifyWifi5(parsed, [{ ...adapters[0], Name: 'Ethernet', InterfaceDescription: 'Wired' }]).wifiIdentified, false);
  assert.equal(identifyWifi5(parsed, [{ ...adapters[0], Status: 'Disconnected' }]).up, false);
  assert.equal(identifyWifi5([], adapters).available, false);
});
test('readiness does not permit payment, raw payload or TLS-key enablement', () => {
  assert.doesNotThrow(() => assertDiagnosticSafety(createTemplate(), {}));
  for (const mutate of [c => { c.execution.networkEnabled = true; }, c => { c.capture.enabled = true; },
    c => { c.capture.interface = '8'; }, c => { c.capture.tlsKeyLoggingEnabled = true; },
    c => { c.evidence.includeResponseBody = true; }]) {
    const cfg = createTemplate(); mutate(cfg); assert.throws(() => assertDiagnosticSafety(cfg, {}), /READINESS_SAFETY_CONFIGURATION_REQUIRED/);
  }
  for (const env of [{ SSLKEYLOGFILE: 'synthetic-path' }, { NODE_OPTIONS: '--tls-keylog=synthetic' }, { NODE_TLS_REJECT_UNAUTHORIZED: '0' }]) {
    assert.throws(() => assertDiagnosticSafety(createTemplate(), env), /READINESS_UNSAFE_TLS_ENVIRONMENT/);
  }
});
test('EPS hostname and exact HTTPS filter are checked without an HTTP/TLS connection', async () => {
  let lookupCalled = 0, compileCalled = 0;
  const result = await checkHostnameAndFilter('synthetic-tshark', {
    resolveHost: async (host, options) => { assert.equal(host, EPS_HOSTNAME); assert.equal(options.all, true); lookupCalled++; return [{ address: '203.0.113.1', family: 4 }]; },
    compile: (_file, args) => { assert.deepEqual(args, ['-i', '5', '-f', INTENDED_EPS_FILTER, '-d']); compileCalled++; return '(000) ret #65535'; }
  });
  assert.equal(lookupCalled, 1); assert.equal(compileCalled, 1);
  assert.equal(result.dnsResolved, true); assert.equal(result.filterCompiled, true); assert.equal(result.apiConnectionAttempted, false);
});
test('DNS and filter failures are explicit and never echo raw resolver/process errors', async () => {
  const sentinel = 'SYNTHETIC_PRIVATE_FAILURE';
  const dnsFail = await checkHostnameAndFilter('synthetic', { resolveHost: async () => { throw new Error(sentinel); } });
  assert.equal(dnsFail.code, 'EPS_DNS_LOOKUP_FAILED');
  const invalid = await checkHostnameAndFilter('synthetic', { resolveHost: async () => [{ address: 'invalid', family: 4 }] });
  assert.equal(invalid.code, 'EPS_DNS_RESULT_INVALID');
  const compileFail = await checkHostnameAndFilter('synthetic', { resolveHost: async () => [{ address: '203.0.113.1', family: 4 }], compile: () => { throw new Error(sentinel); } });
  assert.equal(compileFail.code, 'EPS_FILTER_COMPILE_FAILED');
  assert.ok(!JSON.stringify([dnsFail, invalid, compileFail]).includes(sentinel));
});

const frameOptions = { port: 54321, startedAt: '2026-10-28T00:00:00Z', completedAt: '2026-10-28T00:00:02Z', requirePackets: true };
const epoch = Date.parse(frameOptions.startedAt) / 1000;
const frames = [0, 1, 2].map(i => `${epoch + i / 10}|127.0.0.1|127.0.0.1|${55000 + i}|54321|0|${i}`).join('\n');
test('packet evidence checks counts, three streams, zero payload and UTC timestamps', () => {
  const result = analyzeLocalFrames(frames, frameOptions);
  assert.equal(result.packetCount, 3); assert.equal(result.tcpStreamCount, 3);
  assert.equal(result.applicationPayloadBytes, 0); assert.equal(result.timestampsValid, true);
  assert.equal(result.clientToServerPackets, 3); assert.equal(result.serverToClientPackets, 0);
});
test('Wi-Fi permission evidence requires zero packets', () => {
  assert.equal(analyzeLocalFrames('', { requirePackets: false }).packetCount, 0);
  assert.throws(() => analyzeLocalFrames(frames, { requirePackets: false }), /WIFI_PERMISSION_PROBE_COLLECTED_PACKETS/);
});
for (const [label, text, code] of [
  ['empty', '', 'LOOPBACK_PACKETS_MISSING'],
  ['external address', frames.replace('127.0.0.1', '203.0.113.1'), 'PCAP_NOT_SYNTHETIC_LOOPBACK_ONLY'],
  ['payload', frames.replace('|0|0', '|8|0'), 'PCAP_NOT_SYNTHETIC_LOOPBACK_ONLY'],
  ['wrong port', frames.replace(/54321/g, '443'), 'PCAP_NOT_SYNTHETIC_LOOPBACK_ONLY'],
  ['stale time', frames.replace(String(epoch), String(epoch - 100)), 'PCAP_TIMESTAMP_VALIDATION_FAILED'],
  ['missing stream', frames.split('\n').slice(0, 2).join('\n'), 'LOOPBACK_STREAM_COUNT_MISMATCH']
]) test('packet evidence rejects ' + label, () => assert.throws(() => analyzeLocalFrames(text, frameOptions), new RegExp(code)));
