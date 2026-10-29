import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createTemplate, createLocalConfig, REQUIRED_ENV_NAMES, CREDENTIAL_ENV_NAMES, ENDPOINTS } from '../src/eps-contract.mjs';
import { DEFAULT_CONFIG, EXAMPLE_CONFIG, loadConfig, validateConfig, validateEnvironment } from '../src/config.mjs';
import { CALLBACK_PATHS, callbackIsolationIssue, executionSafetySummary, EXECUTION_BLOCKERS } from '../src/execution-safety.mjs';
import { validateEpsRequest } from '../src/request-contract.mjs';
import { initializeBody, request, privateContext, syntheticEnvironment } from './synthetic-fixtures.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
function callbacks(origin = privateContext.callbackOrigin) {
  return Object.fromEntries(Object.entries(CALLBACK_PATHS).map(([key, value]) => [key, origin + value]));
}
function temporary(t) {
  const parent = path.join(root, 'tmp'); fs.mkdirSync(parent, { recursive: true });
  const dir = fs.mkdtempSync(path.join(parent, 'security-test-'));
  t.after(() => { for (const name of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, name)); fs.rmdirSync(dir); if (!fs.readdirSync(parent).length) fs.rmdirSync(parent); });
  return dir;
}

test('local config is credential-free, ignored, separately profiled and PCAPNG-ready as a plan', () => {
  const cfg = loadConfig(); assert.equal(DEFAULT_CONFIG.endsWith('config.eps.sandbox.local.json'), true);
  assert.deepEqual(cfg, createLocalConfig()); assert.deepEqual(validateConfig(cfg), []);
  assert.deepEqual(validateConfig(loadConfig(EXAMPLE_CONFIG)), []);
  assert.equal(cfg.profile, 'standalone-local'); assert.equal(cfg.capture.enabled, false);
  assert.equal(cfg.capture.interface, '5'); assert.equal(cfg.capture.format, 'pcapng');
  assert.equal(cfg.capture.fileName, 'session.pcapng'); assert.equal(cfg.capture.preservePcap, true);
  assert.equal(cfg.capture.readinessRequired, true); assert.equal(cfg.capture.abortOnFailure, true);
  assert.match(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), /^config\.eps\.sandbox\.local\.json$/m);
  assert.equal(cfg.steps[0].body.userName.env, CREDENTIAL_ENV_NAMES[0]);
  assert.equal(cfg.steps[0].body.password.env, CREDENTIAL_ENV_NAMES[1]);
  assert.equal(cfg.steps[0].signing.keyEnv, CREDENTIAL_ENV_NAMES[2]);
  assert.equal(cfg.steps[1].body.merchantId.env, CREDENTIAL_ENV_NAMES[3]);
  assert.equal(cfg.steps[1].body.storeId.env, CREDENTIAL_ENV_NAMES[4]);
});
for (const stepIndex of [0, 1, 2]) test('local config allowlists the exact endpoint for step ' + stepIndex, () => {
  for (const mutate of [url => url.replace('https:', 'http:'), url => url.replace('sandboxpgapi.eps.com.bd', 'other.example.com'),
    url => url + '?extra=synthetic', url => url + '#fragment', url => url + '/',
    url => url.replace('.com.bd/', '.com.bd:443/'), url => url.replace('/v1/', '/v2/')]) {
    const cfg = createLocalConfig(); cfg.steps[stepIndex].url = mutate(cfg.steps[stepIndex].url);
    assert.ok(validateConfig(cfg).length > 0);
  }
  assert.equal(createLocalConfig().steps[stepIndex].url, Object.values(ENDPOINTS)[stepIndex]);
});
for (const key of ['includeRequestHeaders', 'includeResponseHeaders', 'includeRequestBody', 'includeResponseBody']) {
  test('local config prohibits raw sensitive evidence flag ' + key, () => {
    const cfg = createLocalConfig(); cfg.evidence[key] = true; assert.ok(validateConfig(cfg).length);
  });
}
for (const [label, mutate] of [
  ['capture enablement', c => { c.capture.enabled = true; }],
  ['TLS key logging', c => { c.capture.tlsKeyLoggingEnabled = true; }],
  ['PCAP name traversal', c => { c.capture.fileName = '../synthetic.pcapng'; }],
  ['wrong output format', c => { c.capture.format = 'pcap'; }],
  ['wrong adapter', c => { c.capture.interface = '8'; }],
  ['skip readiness', c => { c.capture.readinessRequired = false; }],
  ['ignore capture failure', c => { c.capture.abortOnFailure = false; }],
  ['disable local PCAP retention', c => { c.capture.preservePcap = false; }],
  ['network enablement', c => { c.execution.networkEnabled = true; }],
  ['automatic retry', c => { c.execution.automaticRetries = 1; }],
  ['callback enablement', c => { c.execution.callbacksEnabled = true; }],
  ['disable durable tracking', c => { c.safety.attemptTracking.restartSafeRequired = false; }],
  ['persist tokens', c => { c.safety.attemptTracking.persistTokens = true; }],
  ['automatic restart resume', c => { c.safety.attemptTracking.automaticRestartResume = true; }],
  ['self-confirm callback approval', c => { c.safety.callbackIsolation.receiverOwnership = 'CONFIRMED'; }],
  ['erase blocker list', c => { c.safety.blockers = []; }]
]) test('local safety rejects ' + label, () => { const cfg = createLocalConfig(); mutate(cfg); assert.ok(validateConfig(cfg).length); });

test('restart-safe tracking is prepared for account-scoped live attempts while execution remains blocked', () => {
  const policy = createLocalConfig().safety.attemptTracking;
  assert.equal(policy.requiredBeforeInitialize, true); assert.equal(policy.atomicReservationRequired, true);
  assert.equal(policy.restartSafeRequired, true); assert.equal(policy.storage, 'private-atomic-journal-prepared-for-account-scoped-live-attempts');
  assert.deepEqual(policy.uniqueFields, ['merchantTransactionId', 'CustomerOrderId']);
  assert.equal(policy.uncertainInitialization, 'block-new-initialization-and-require-reconciliation');
  for (const key of ['persistCredentials', 'persistTokens', 'persistCustomerData', 'persistSignedUrls', 'automaticRestartResume']) assert.equal(policy[key], false);
  assert.equal(executionSafetySummary().executionReady, false);
  assert.ok(executionSafetySummary().blockers.includes('LIVE_ATTEMPT_LEDGER_SCOPE_NOT_APPROVED'));
  assert.deepEqual(createLocalConfig().safety.blockers, [...EXECUTION_BLOCKERS]);
});
test('isolated callbacks use one approved-origin placeholder and distinct diagnostic paths', () => {
  assert.equal(callbackIsolationIssue(callbacks(), privateContext), null);
  assert.equal(validateEpsRequest('INITIALIZE', request('INITIALIZE'), privateContext).accepted, true);
  const { callbackOrigin, ecommerceOrigins, ...missingIsolation } = privateContext;
  assert.equal(validateEpsRequest('INITIALIZE', request('INITIALIZE'), missingIsolation).code, 'ISOLATED_CALLBACK_ORIGIN_REQUIRED');
});
for (const [index, origin] of ['https://shop.example.com', 'https://SHOP.EXAMPLE.COM:443', 'https://shop.example.com.', 'https://shop.example.com:8443'].entries()) {
  test('known ecommerce hostname is blocked regardless of case/port/trailing dot: variant ' + index, () => {
    assert.equal(callbackIsolationIssue(callbacks(origin), privateContext), 'ECOMMERCE_CALLBACK_TARGET_FORBIDDEN');
    assert.equal(callbackIsolationIssue(callbacks(origin), { ...privateContext, callbackOrigin: origin }), 'ECOMMERCE_CALLBACK_TARGET_FORBIDDEN');
  });
}
for (const [index, unsafePath] of ['/api/eps/success', '/API/EPS/SUCCESS', '/api/%65ps/success', '/api/%2565ps/success', '//api//eps/success', '/api/aibl-wallet/approved'].entries()) {
  test('ecommerce callback route and encoded aliases are blocked ' + index, () => {
    const urls = callbacks(); urls.successUrl = privateContext.callbackOrigin + unsafePath;
    assert.equal(callbackIsolationIssue(urls, privateContext), 'ECOMMERCE_CALLBACK_ROUTE_FORBIDDEN');
  });
}
for (const [index, value] of ['https://callbacks.example.com/eps-trace/fail',
  'https://other.example.com/eps-trace/success', 'https://callbacks.example.com/eps-trace/success?attempt=synthetic&state=synthetic',
  'https://callbacks.example.com/eps-trace/success#fragment', 'https://synthetic:synthetic@callbacks.example.com/eps-trace/success',
  'https://callbacks.example.com\\api\\eps\\success', 'http://callbacks.example.com/eps-trace/success'].entries()) {
  test('callback ambiguity or unconfirmed delivery details fail closed ' + index, () => {
    const urls = callbacks(); urls.successUrl = value; assert.notEqual(callbackIsolationIssue(urls, privateContext), null);
  });
}
test('missing, invalid or duplicate ecommerce-origin denylist is not treated as isolated', () => {
  for (const ecommerceOrigins of [undefined, [], {}, ['http://localhost:3000'], ['https://shop.example.com/path'],
    ['https://shop.example.com', 'https://SHOP.EXAMPLE.COM:443'], new Array(33).fill('https://shop.example.com')]) {
    assert.notEqual(callbackIsolationIssue(callbacks(), { ...privateContext, ecommerceOrigins }), null);
  }
  for (const callbackOrigin of [undefined, '', 'https://callbacks.example.com/path', 'https://callbacks.example.com?secret=synthetic']) {
    assert.equal(callbackIsolationIssue(callbacks(), { ...privateContext, callbackOrigin }), 'ISOLATED_CALLBACK_ORIGIN_REQUIRED');
  }
});
test('private environment preflight requires callback isolation without reading ecommerce .env', () => {
  const env = syntheticEnvironment(); assert.deepEqual(validateEnvironment(env), []);
  for (const key of ['EPS_TRACE_CALLBACK_ORIGIN', 'EPS_TRACE_ECOMMERCE_ORIGINS']) {
    const missing = { ...env }; delete missing[key]; assert.ok(validateEnvironment(missing).includes('ENV_MISSING:' + key));
  }
  assert.ok(validateEnvironment({ ...env, EPS_TRACE_ECOMMERCE_ORIGINS: '{synthetic-invalid' }).includes('ECOMMERCE_ORIGIN_DENYLIST_INVALID'));
  assert.ok(validateEnvironment({ ...env, EPS_TRACE_ECOMMERCE_ORIGINS: '[]' }).includes('ECOMMERCE_ORIGIN_DENYLIST_REQUIRED'));
  const targetApp = { ...env, EPS_TRACE_CALLBACK_ORIGIN: 'https://shop.example.com' };
  assert.ok(validateEnvironment(targetApp).includes('ECOMMERCE_CALLBACK_TARGET_FORBIDDEN'));
});
test('safety diagnostics do not expose private callback URLs or credential values', () => {
  const env = syntheticEnvironment(); env.EPS_TRACE_SUCCESS_URL = 'https://shop.example.com/eps-trace/success?private=SYNTHETIC_PRIVATE_SENTINEL';
  const result = JSON.stringify(validateEnvironment(env));
  assert.ok(!result.includes('https://')); assert.ok(!result.includes('SYNTHETIC_PRIVATE_SENTINEL'));
  assert.ok(!result.includes(env.EPS_PASSWORD)); assert.ok(!result.includes(env.EPS_HASH_KEY));
});
test('config loading rejects duplicate keys instead of silently taking a safe-looking final value', t => {
  const dir = temporary(t), file = path.join(dir, 'duplicate.json');
  fs.writeFileSync(file, '{"execution":{"networkEnabled":true,"networkEnabled":false}}');
  assert.throws(() => loadConfig(file), /CONFIG_READ_OR_PARSE_FAILED/);
  fs.writeFileSync(file, Buffer.from([0xc3, 0x28]));
  assert.throws(() => loadConfig(file), /CONFIG_READ_OR_PARSE_FAILED/);
});
test('inline credentials and unsupported config keys are rejected without echoing their values', () => {
  const cfg = createLocalConfig(); cfg.steps[0].body.password = 'SYNTHETIC_PRIVATE_PASSWORD'; cfg.credentials = { token: 'SYNTHETIC_PRIVATE_TOKEN' };
  const text = JSON.stringify(validateConfig(cfg)); assert.ok(!text.includes('SYNTHETIC_PRIVATE')); assert.ok(validateConfig(cfg).length);
});
test('CLI default local config is valid while execution readiness remains false', () => {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^EPS_/i.test(key)));
  Object.assign(env, { NODE_OPTIONS: '', SSLKEYLOGFILE: '', NODE_TLS_REJECT_UNAUTHORIZED: '1' });
  const output = spawnSync(process.execPath, ['--require', path.join(root, 'tests/no-network.cjs'), path.join(root, 'src/cli.mjs'), 'validate'], {
    cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 5000
  });
  assert.equal(output.status, 0); const result = JSON.parse(output.stdout);
  assert.equal(result.valid, true); assert.equal(result.executionReady, false);
  assert.ok(result.blockers.includes('ISOLATED_CALLBACK_RECEIVER_OWNERSHIP_UNCONFIRMED'));
});
