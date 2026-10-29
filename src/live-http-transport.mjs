import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { ENDPOINTS } from './eps-contract.mjs';
import { validateEpsRequest } from './request-contract.mjs';
import { assertLiveExecutionCapability } from './live-execution-gate.mjs';

const STEP_NAMES = Object.freeze(Object.keys(ENDPOINTS));

function transportError(code) { const error = new Error(code); error.code = code; return error; }

function createTransport(options) {
  const { timeoutMs = 20000, maxResponseBytes = 32768, lookup, ca, port = 443,
    servername, localTest = false } = options;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000 ||
      !Number.isInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 32768) {
    throw transportError('LIVE_TRANSPORT_LIMITS_INVALID');
  }
  const used = new Set();
  return Object.freeze({
    async exchange(step, request, context) {
      if (used.has(step)) throw transportError('LIVE_AUTOMATIC_RETRY_FORBIDDEN');
      if (!STEP_NAMES.includes(step) || !validateEpsRequest(step, request, context).accepted) {
        throw transportError('LIVE_REQUEST_CONTRACT_REJECTED');
      }
      const parsed = new URL(request.url);
      if (parsed.origin + parsed.pathname !== ENDPOINTS[step]) throw transportError('LIVE_DESTINATION_REJECTED');
      used.add(step);
      return new Promise((resolve, reject) => {
        const started = performance.now();
        let dnsStart = null, dnsEnd = null, tcp = null, tls = null, first = null, settled = false, bytes = 0;
        const safeTiming = () => ({
          source: localTest ? 'local-live-transport-test' : 'live-measurement',
          dnsPerformed: dnsStart !== null,
          dnsMs: dnsStart === null || dnsEnd === null ? null : dnsEnd - dnsStart,
          tcpConnectMs: tcp === null ? null : tcp - started,
          tlsHandshakeMs: tcp === null || tls === null ? null : tls - tcp,
          firstByteMs: first === null ? null : first - started,
          totalMs: performance.now() - started,
          tlsVerified: tls !== null
        });
        const finish = (error, value) => {
          if (settled) return;
          settled = true; clearTimeout(deadline);
          error ? reject(transportError(error)) : resolve({ ...value, timing: safeTiming() });
        };
        const measuredLookup = lookup ? (hostname, lookupOptions, callback) => {
          dnsStart = performance.now();
          lookup(hostname, lookupOptions, (error, address, family) => {
            dnsEnd = performance.now(); callback(error, address, family);
          });
        } : undefined;
        const req = https.request({
          protocol: 'https:', hostname: parsed.hostname, port, path: parsed.pathname + parsed.search,
          method: request.method, headers: request.headers, agent: false, lookup: measuredLookup,
          servername, ca, rejectUnauthorized: true, minVersion: 'TLSv1.2', maxRedirects: 0
        }, res => {
          first = performance.now();
          const chunks = [];
          res.on('data', chunk => {
            bytes += chunk.length;
            if (bytes > maxResponseBytes) { finish('LIVE_RESPONSE_SIZE_LIMIT'); res.destroy(); req.destroy(); }
            else chunks.push(chunk);
          });
          res.on('end', () => finish(null, { httpStatus: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
          res.on('aborted', () => finish('LIVE_RESPONSE_ABORTED'));
          res.on('error', () => finish('LIVE_RESPONSE_ABORTED'));
        });
        const deadline = setTimeout(() => { finish('LIVE_HTTP_TIMEOUT'); req.destroy(); }, timeoutMs);
        req.on('socket', socket => {
          socket.once('connect', () => {
            tcp = performance.now();
            if (localTest && socket.remoteAddress !== '127.0.0.1') { finish('LIVE_LOCAL_DESTINATION_REJECTED'); req.destroy(); }
          });
          socket.once('secureConnect', () => {
            if (!socket.authorized) { finish('LIVE_TLS_VALIDATION_FAILED'); req.destroy(); }
            else tls = performance.now();
          });
        });
        req.on('upgrade', (res, socket) => { first = performance.now(); finish(null, { httpStatus: res.statusCode, body: '' }); socket.destroy(); });
        req.on('error', error => finish(error?.code === 'CERT_HAS_EXPIRED' ? 'LIVE_TLS_VALIDATION_FAILED' : 'LIVE_TRANSPORT_FAILURE'));
        if (request.body !== null) req.write(request.body);
        req.end();
      });
    }
  });
}

export function createLiveEpsTransport(capability, network = {}) {
  assertLiveExecutionCapability(capability);
  return createTransport({ timeoutMs: network.timeoutMs, maxResponseBytes: network.maxResponseBytes });
}

// Fixed loopback adapter for tests. The request still carries the exact EPS URL,
// while lookup is forced to 127.0.0.1 and cannot resolve or reach EPS.
export function createLocalLiveTransportTestHarness({ port, ca, timeoutMs = 1000, maxResponseBytes = 32768 } = {}) {
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !ca) throw transportError('LIVE_LOCAL_HARNESS_INVALID');
  const lookup = (_hostname, options, callback) => queueMicrotask(() => options?.all
    ? callback(null, [{ address:'127.0.0.1', family:4 }]) : callback(null, '127.0.0.1', 4));
  return createTransport({ port, ca, timeoutMs, maxResponseBytes, lookup, servername: '127.0.0.1', localTest: true });
}
