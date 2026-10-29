import { syntheticEnvironment as environment } from './synthetic-fixtures.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createTemplate, REQUIRED_ENV_NAMES } from '../src/eps-contract.mjs';
import { EXAMPLE_CONFIG, loadConfig, validateConfig, validateEnvironment } from '../src/config.mjs';
import { epsXHash } from '../src/signing.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const guard = path.join(root, 'tests/no-network.cjs');
const cli = path.join(root, 'src/cli.mjs');
function command(args, cwd = root) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^EPS_/i.test(key)));
  Object.assign(env, { NODE_OPTIONS: '', SSLKEYLOGFILE: '', NODE_TLS_REJECT_UNAUTHORIZED: '1' });
  return spawnSync(process.execPath, ['--require', guard, cli, ...args], {
    cwd, env, encoding: 'utf8', windowsHide: true, timeout: 5000
  });
}

test('stored template is structurally valid, offline and uses Web type 1', () => {
  const cfg = loadConfig(EXAMPLE_CONFIG);
  assert.deepEqual(validateConfig(cfg), []);
  assert.deepEqual(cfg, createTemplate());
  assert.equal(cfg.execution.networkEnabled, false);
  assert.equal(cfg.capture.enabled, false);
  assert.equal(cfg.capture.tlsKeyLoggingEnabled, false);
  assert.equal(cfg.steps[1].body.transactionTypeId, 1);
  assert.equal(cfg.steps[1].body.totalAmount.type, 'number');
});

test('exact Sandbox endpoints, field casing, hash inputs and Bearer binding', () => {
  const [auth, init, status] = createTemplate().steps;
  assert.equal(auth.method, 'POST'); assert.equal(auth.url, 'https://sandboxpgapi.eps.com.bd/v1/Auth/GetToken');
  assert.deepEqual(Object.keys(auth.body).sort(), ['password', 'userName']);
  assert.equal(auth.signing.inputEnv, 'EPS_USERNAME');
  assert.equal(auth.headers.Authorization, undefined);
  assert.equal(init.method, 'POST'); assert.equal(init.url, 'https://sandboxpgapi.eps.com.bd/v1/EPSEngine/InitializeEPS');
  assert.equal(init.signing.inputEnv, 'EPS_TRACE_MERCHANT_TRANSACTION_ID');
  assert.equal(init.body.merchantId.env, 'EPS_MERCHANT_ID');
  assert.equal(init.body.CustomerOrderId.env, 'EPS_TRACE_CUSTOMER_ORDER_ID');
  assert.equal(init.body.customerAddress.env, 'EPS_TRACE_CUSTOMER_ADDRESS');
  assert.equal(status.method, 'GET'); assert.equal(status.url, 'https://sandboxpgapi.eps.com.bd/v1/EPSEngine/CheckMerchantTransactionStatus');
  assert.equal(status.body, null);
  assert.equal(status.query.merchantTransactionId.env, init.body.merchantTransactionId.env);
  for (const step of [init, status]) assert.deepEqual(step.headers.Authorization, { scheme: 'Bearer', variable: 'EPS_TOKEN' });
  for (const step of [auth, init, status]) {
    assert.equal(step.headers['Content-Type'], 'application/json');
    assert.equal(step.signing.header, 'x-hash');
    assert.equal(step.signing.keyEncoding, 'utf8');
    assert.equal(step.signing.outputEncoding, 'base64');
  }
});

const mutations = [
  ['network enablement', c => { c.execution.networkEnabled = true; }],
  ['payment enablement', c => { c.execution.paymentRequestsEnabled = true; }],
  ['capture enablement', c => { c.capture.enabled = true; }],
  ['TLS key collection', c => { c.capture.tlsKeyLoggingEnabled = true; }],
  ['raw payloads', c => { c.evidence.includeRequestBody = true; }],
  ['TLS bypass', c => { c.network.rejectUnauthorized = false; }],
  ['non-sandbox destination', c => { c.steps[0].url = 'https://elsewhere.example.com/v1/Auth/GetToken'; }],
  ['wrong Web sample 10', c => { c.steps[1].body.transactionTypeId = 10; }],
  ['string amount wire type', c => { c.steps[1].body.totalAmount.type = 'string'; }],
  ['inline password', c => { c.steps[0].body.password = 'synthetic-inline-secret'; }],
  ['inline hash key', c => { c.steps[0].signing.keyEnv = 'synthetic-inline-secret'; }],
  ['inline JWT', c => { c.steps[1].headers.Authorization = 'Bearer synthetic-inline-token'; }],
  ['wrong hash input', c => { c.steps[1].signing.inputEnv = 'EPS_USERNAME'; }],
  ['GET body', c => { c.steps[2].body = { merchantTransactionId: 'synthetic-reference' }; }],
  ['extra optional payload field', c => { c.steps[1].body.financialEntityId = 0; }]
];
for (const [label, mutate] of mutations) test('rejects ' + label, () => {
  const cfg = createTemplate(); mutate(cfg); assert.ok(validateConfig(cfg).length > 0);
});

test('HMAC-SHA512 Base64 matches RFC 4231 public synthetic vector', () => {
  const expectedHex = '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
    'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854';
  assert.equal(epsXHash('Hi There', '\x0b'.repeat(20)), Buffer.from(expectedHex, 'hex').toString('base64'));
  assert.throws(() => epsXHash('', 'synthetic-key'), /SIGNING_INPUT_INVALID/);
  assert.throws(() => epsXHash('synthetic-input', ''), /SIGNING_INPUT_INVALID/);
});

test('environment preflight accepts synthetic values and reports names only', () => {
  assert.deepEqual(validateEnvironment(environment()), []);
  const issues = validateEnvironment({});
  assert.equal(issues.length, REQUIRED_ENV_NAMES.length);
  assert.ok(issues.every(x => /^ENV_MISSING:EPS_[A-Z_]+$/.test(x)));
  const invalid = environment(); invalid.EPS_TRACE_AMOUNT = '0.00'; invalid.EPS_TRACE_MERCHANT_TRANSACTION_ID = 'not-numeric';
  invalid.EPS_TRACE_SUCCESS_URL = 'http://localhost/synthetic-sensitive-path'; invalid.SSLKEYLOGFILE = 'synthetic-key-path';
  const output = JSON.stringify(validateEnvironment(invalid));
  assert.match(output, /AMOUNT_FORMAT_INVALID/); assert.match(output, /CALLBACK_URL_FORMAT_INVALID/);
  assert.match(output, /EXTERNAL_TLS_KEYLOG_FORBIDDEN/);
  assert.ok(!output.includes('synthetic-sensitive-path')); assert.ok(!output.includes('synthetic-key-path'));
});

for (const name of ['auth', 'initialize', 'status', 'trace', 'run']) test(name + ' execution is denied before config or credentials are loaded', () => {
  const result = command([name, '--config', 'missing-file.json', '--allow-network']);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).error, 'PAYMENT_API_EXECUTION_DISABLED_OFFLINE');
  assert.equal(result.stdout, '');
});

test('CLI validation works offline and never loads a local .env file', () => {
  const valid = command(['validate']); assert.equal(valid.status, 0); assert.equal(JSON.parse(valid.stdout).valid, true);
  const parent = path.join(root, 'tmp'); fs.mkdirSync(parent, { recursive: true });
  const dir = fs.mkdtempSync(path.join(parent, 'step1-')); const envPath = path.join(dir, '.env');
  try {
    fs.writeFileSync(envPath, Object.entries(environment()).map(([k, v]) => k + '=' + v).join('\n'));
    const result = command(['validate', '--check-env'], dir);
    assert.equal(result.status, 1); const report = JSON.parse(result.stdout);
    assert.ok(report.issues.includes('ENV_MISSING:EPS_USERNAME'));
    assert.ok(!result.stdout.includes('synthetic-test-password'));
  } finally {
    fs.unlinkSync(envPath); fs.rmdirSync(dir);
    if (fs.readdirSync(parent).length === 0) fs.rmdirSync(parent);
  }
});

test('only reviewed transport modules may import HTTPS; no source imports app/database code', () => {
  for (const name of fs.readdirSync(path.join(root, 'src'))) {
    const source = fs.readFileSync(path.join(root, 'src', name), 'utf8');
    if (!['mock-transport.mjs','live-http-transport.mjs','auth-only-http.mjs'].includes(name)) assert.doesNotMatch(source, /from\s+['"](?:node:)?(?:http|https|tls|dgram)['"]|\bfetch\s*\(/);
    else if (name === 'mock-transport.mjs') { assert.match(source, /hostname:'127\.0\.0\.1'/); assert.doesNotMatch(source, /sandboxpgapi\.eps\.com\.bd/); }
    else if(name==='live-http-transport.mjs') { assert.match(source,/assertLiveExecutionCapability/);assert.match(source,/127\.0\.0\.1/);assert.doesNotMatch(source,/NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized:\s*false/); }
    else {assert.match(source,/AUTH_ONLY_ENDPOINT/);assert.match(source,/\/v1\/Auth\/GetToken/);assert.doesNotMatch(source,/InitializeEPS|CheckMerchantTransactionStatus|rejectUnauthorized:\s*false/);}
    if (name !== 'network-readiness.mjs') assert.doesNotMatch(source, /from\s+['"]node:(?:net|dns\/promises)['"]/);
    assert.doesNotMatch(source, /from\s+['"][^'"]*(?:prisma|general_ecommerce|deshiplus_payment_trace)[^'"]*['"]/);
  }
});
