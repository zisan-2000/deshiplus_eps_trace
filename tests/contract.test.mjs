import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { epsXHash } from '../src/signing.mjs';
import { normalizeAmount, MAX_JSON_BYTES, MAX_TOKEN_CHARS } from '../src/contract-utils.mjs';
import { validateEpsResponse, validateEpsPayload } from '../src/response-contract.mjs';
import { validateEpsRequest, createIdentityRegistry, INITIALIZE_FIELDS } from '../src/request-contract.mjs';
import { identity, privateContext, payload, request, initializeBody } from './synthetic-fixtures.mjs';

const steps = ['AUTH', 'INITIALIZE', 'STATUS'];
const response = (step, value = payload(step), context = identity) =>
  validateEpsResponse(step, { httpStatus: 200, body: JSON.stringify(value) }, context);
const reject = (value, code) => { assert.equal(value.accepted, false); assert.equal(value.paymentVerified, false); if (code) assert.equal(value.code, code); };

for (const step of steps) test(step + ' accepts the exact synthetic reference exchange', () => {
  assert.equal(validateEpsRequest(step, request(step), privateContext).accepted, true);
  const result = response(step); assert.equal(result.accepted, true);
  assert.equal(result.paymentVerified, step === 'STATUS');
});

for (const status of [101, 199, 300, 302, 400, 401, 500]) test('HTTP ' + status + ' cannot become business success', () => {
  for (const step of steps) {
    const result = validateEpsResponse(step, { httpStatus: status, body: JSON.stringify(payload(step)) }, identity);
    reject(result, 'HTTP_STATUS_REJECTED'); assert.equal(result.outcome, 'HTTP_FAILURE');
  }
});
test('HTTP status must be a parsed integer, never a JSON gateway code', () => {
  for (const httpStatus of [undefined, null, '200', NaN, 200.5]) {
    reject(validateEpsResponse('AUTH', { httpStatus, body: JSON.stringify(payload('AUTH')) }), 'HTTP_STATUS_INVALID');
  }
  const result = response('STATUS', { ...payload('STATUS'), ErrorCode: 101 });
  reject(result, 'GATEWAY_ERROR_REPORTED'); assert.equal(result.outcome, 'BUSINESS_FAILURE');
});

for (const [label, body] of [['empty', ''], ['broken', '{'], ['null', 'null'], ['array', '[]'], ['boolean', 'true'], ['number', '0'], ['string', '"opaque"']]) {
  test('rejects ' + label + ' JSON document for every step', () => {
    for (const step of steps) reject(validateEpsResponse(step, { httpStatus: 200, body }, identity));
  });
}
test('rejects invalid UTF-8 and absent JSON documents', () => {
  reject(validateEpsResponse('AUTH', { httpStatus: 200, body: Buffer.from([0xc3, 0x28]) }), 'INVALID_UTF8');
  reject(validateEpsResponse('AUTH', { httpStatus: 200, body: payload('AUTH') }), 'JSON_DOCUMENT_REQUIRED');
});
test('JSON byte boundary is enforced without storing or returning the body', () => {
  const base = JSON.stringify(payload('AUTH'));
  assert.equal(validateEpsResponse('AUTH', { httpStatus: 200, body: base + ' '.repeat(MAX_JSON_BYTES - Buffer.byteLength(base)) }).accepted, true);
  reject(validateEpsResponse('AUTH', { httpStatus: 200, body: base + ' '.repeat(MAX_JSON_BYTES - Buffer.byteLength(base) + 1) }), 'JSON_SIZE_LIMIT_EXCEEDED');
});
for (const [label, body] of [
  ['root duplicate', '{"token":"synthetic-a","token":"synthetic-b"}'],
  ['escaped duplicate', '{"token":"synthetic-a","to\\u006ben":"synthetic-b"}'],
  ['nested duplicate', '{"token":"synthetic-a","extra":{"key":1,"key":2}}']
]) test('rejects ' + label + ' JSON keys', () => reject(validateEpsResponse('AUTH', { httpStatus: 200, body }), 'DUPLICATE_JSON_KEY'));
test('duplicate key tracking is scoped to each object', () => {
  assert.equal(response('AUTH', { ...payload('AUTH'), extra: [{ key: 1 }, { key: 2 }] }).accepted, true);
});
test('rejects excessive JSON nesting', () => {
  const body = '{"token":"synthetic","extra":' + '['.repeat(33) + '0' + ']'.repeat(33) + '}';
  reject(validateEpsResponse('AUTH', { httpStatus: 200, body }), 'JSON_DEPTH_LIMIT_EXCEEDED');
});
test('payload helper rejects arrays, special objects and inherited fields', () => {
  for (const value of [null, [], new Date(), new Map(), Object.create({ token: 'synthetic' })]) reject(validateEpsPayload('AUTH', value), 'JSON_OBJECT_REQUIRED');
  reject(validateEpsPayload('UNKNOWN', {}), 'UNKNOWN_EPS_STEP');
});

const badTokens = ['', ' ', ' synthetic', 'synthetic ', 'synthetic\nvalue', 'synthetic\rvalue',
  'synthetic\tvalue', 'synthetic\u0000value', 'opaque-চাবি', 'synthetic:token', 'synthetic,token',
  'synthetic"token', 'synthetic=inside=value', null, 123, false, [], {}, 'x'.repeat(MAX_TOKEN_CHARS + 1)];
badTokens.forEach((token, index) => test('AUTH rejects invalid opaque token ' + index, () => reject(response('AUTH', { token }), 'AUTH_TOKEN_INVALID')));
test('AUTH accepts bounded opaque tokens without inventing JWT decoding', () => {
  assert.equal(response('AUTH', { token: 'x'.repeat(MAX_TOKEN_CHARS) }).accepted, true);
  assert.equal(response('AUTH', { token: 'opaque-not-a-jwt' }).accepted, true);
  assert.equal(response('AUTH', { token: 'opaque._~+/-==' }).accepted, true);
});
for (const step of steps) test(step + ' rejects response casing aliases even alongside the canonical key', () => {
  const canonical = { AUTH: 'token', INITIALIZE: 'RedirectURL', STATUS: 'MerchantTransactionId' }[step];
  const alias = { AUTH: 'Token', INITIALIZE: 'RedirectUrl', STATUS: 'merchantTransactionId' }[step];
  const original = payload(step); original[alias] = original[canonical];
  reject(response(step, original), 'RESPONSE_FIELD_CASING_INVALID');
  delete original[canonical]; reject(response(step, original), 'RESPONSE_FIELD_CASING_INVALID');
  const wrongError = payload(step); wrongError[step === 'AUTH' ? 'ErrorCode' : 'errorCode'] = null;
  reject(response(step, wrongError), 'RESPONSE_FIELD_CASING_INVALID');
});
for (const step of steps) test(step + ' error fields have explicit no-error representations and types', () => {
  const codeKey = step === 'AUTH' ? 'errorCode' : 'ErrorCode';
  const messageKey = step === 'AUTH' ? 'errorMessage' : 'ErrorMessage';
  for (const code of [null, '', 0]) assert.equal(response(step, { ...payload(step), [codeKey]: code, [messageKey]: null }).accepted, true);
  const without = payload(step); delete without[codeKey]; delete without[messageKey]; assert.equal(response(step, without).accepted, true);
  for (const code of ['0', ' ', '101', 101, -1]) reject(response(step, { ...payload(step), [codeKey]: code }), 'GATEWAY_ERROR_REPORTED');
  for (const code of [false, true, [], {}]) reject(response(step, { ...payload(step), [codeKey]: code }), 'ERROR_FIELD_TYPE_INVALID');
  for (const message of [' ', 'synthetic-sensitive-message']) reject(response(step, { ...payload(step), [messageKey]: message }), 'GATEWAY_ERROR_REPORTED');
  for (const message of [false, 0, [], {}]) reject(response(step, { ...payload(step), [messageKey]: message }), 'ERROR_FIELD_TYPE_INVALID');
});

const badRedirects = ['', null, 1, 'http://eps.com.bd/pay', 'javascript:synthetic',
  'https://eps.com.bd.evil.example.com/pay', 'https://other.example.com/pay',
  'https://synthetic:synthetic@eps.com.bd/pay', 'https://eps.com.bd:444/pay',
  'https://eps.com.bd/pay#synthetic', ' https://eps.com.bd/pay', 'https://eps.com.bd/pay ',
  'https://eps.com.bd/pa\ny', 'https://eps.com.bd/pay?x=' + 'x'.repeat(4096)];
badRedirects.forEach((RedirectURL, index) => test('INITIALIZE rejects unsafe redirect ' + index, () => reject(response('INITIALIZE', { RedirectURL }), 'INITIALIZE_REDIRECT_INVALID')));
test('INITIALIZE allows EPS HTTPS hosts and an optional absent/null bank reference', () => {
  for (const host of ['eps.com.bd', 'sandbox.eps.com.bd', 'EPS.COM.BD']) {
    const value = { RedirectURL: 'https://' + host + '/pay?reference=synthetic' };
    assert.equal(response('INITIALIZE', value).accepted, true);
    assert.equal(response('INITIALIZE', { ...value, TransactionId: null }).accepted, true);
  }
});
for (const [index, TransactionId] of [123, false, '', ' ', [], {}, 'x'.repeat(161), 'synthetic\nreference'].entries()) {
  test('INITIALIZE rejects malformed optional bank reference ' + index, () => reject(response('INITIALIZE', { ...payload('INITIALIZE'), TransactionId }), 'INITIALIZE_TRANSACTION_ID_INVALID'));
}

for (const [index, MerchantTransactionId] of [Number(identity.merchantTransactionId), null, '',
  identity.merchantTransactionId.slice(1), identity.merchantTransactionId + ' ', '12345678901234567890123'].entries()) {
  test('STATUS rejects transaction mismatch/type ' + index, () => reject(response('STATUS', { ...payload('STATUS'), MerchantTransactionId }), 'STATUS_TRANSACTION_MISMATCH'));
}
test('STATUS requires the original transaction and positive expected amount context', () => {
  for (const context of [{}, { ...identity, merchantTransactionId: 1234567890 }, { ...identity, amount: '0.00' }, { ...identity, amount: '100.250' }, { ...identity, amount: null }]) {
    reject(response('STATUS', payload('STATUS'), context), 'EXPECTED_TRANSACTION_CONTEXT_REQUIRED');
  }
});
for (const [index, TotalAmount] of ['100.25', 100.25, '00100.25'].entries()) test('STATUS normalizes valid amount representation ' + index, () => assert.equal(response('STATUS', { ...payload('STATUS'), TotalAmount }).paymentVerified, true));
for (const [index, TotalAmount] of ['100.250', '100.24', 100.26, '1e2', '', ' 100.25', -100.25, 0, null, true, [], {}].entries()) {
  test('STATUS rejects amount mismatch/format ' + index, () => reject(response('STATUS', { ...payload('STATUS'), TotalAmount }), 'STATUS_AMOUNT_MISMATCH'));
}
for (const [index, Status] of ['success', 'SUCCESS', 'Success ', ' Success', 'Pending', 'Failed', 'Cancelled', 'Undocumented'].entries()) {
  test('STATUS value ' + index + ' remains unconfirmed without status aliases or guessed terminal states', () => {
    const result = response('STATUS', { ...payload('STATUS'), Status }); reject(result, 'STATUS_NOT_CONFIRMED'); assert.equal(result.outcome, 'PENDING');
  });
}
for (const [index, Status] of ['', ' ', null, 1, false, {}, []].entries()) test('STATUS rejects malformed status field ' + index, () => reject(response('STATUS', { ...payload('STATUS'), Status }), 'STATUS_FIELD_INVALID'));
test('STATUS requires canonical fields and never infers success from aliases', () => {
  for (const key of ['MerchantTransactionId', 'TotalAmount', 'Status']) { const value = payload('STATUS'); delete value[key]; reject(response('STATUS', value)); }
  const value = payload('STATUS'); value.status = value.Status; reject(response('STATUS', value), 'RESPONSE_FIELD_CASING_INVALID');
});
test('all response results omit private fields and arbitrary provider messages', () => {
  const sentinel = 'SYNTHETIC_PRIVATE_SENTINEL';
  const results = [response('AUTH', { token: sentinel }), response('INITIALIZE', { RedirectURL: 'https://eps.com.bd/pay?token=' + sentinel }),
    response('STATUS', { ...payload('STATUS'), ErrorMessage: sentinel }), response('STATUS')];
  const text = JSON.stringify(results);
  assert.ok(!text.includes(sentinel)); assert.ok(!text.includes(identity.merchantTransactionId));
  assert.ok(!text.includes('https://')); assert.ok(!text.includes(privateContext.token));
});

test('amount normalization never rounds or accepts non-JSON money objects', () => {
  for (const [input, expected] of [['1', '1.00'], ['001.2', '1.20'], [0.1, '0.10'], ['99999999.99', '99999999.99']]) assert.equal(normalizeAmount(input), expected);
  for (const value of [0.1 + 0.2, '1.234', '1e2', '100000000', '-1', Infinity, NaN, true, {}, 1n]) assert.equal(normalizeAmount(value), null);
});
test('HMAC-SHA512 matches a second independent RFC 4231 vector', () => {
  const hex = '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554' +
    '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737';
  assert.equal(epsXHash('what do ya want for nothing?', 'Jefe'), Buffer.from(hex, 'hex').toString('base64'));
});
test('hash keys use UTF-8 text rather than Base64 decoding and inputs are not trimmed', () => {
  const key = 'c3ludGhldGljLWtleQ==', input = 'synthetic-user';
  assert.notEqual(epsXHash(input, key), createHmac('sha512', Buffer.from(key, 'base64')).update(input, 'utf8').digest('base64'));
  assert.notEqual(epsXHash(input, key), epsXHash(input + ' ', key));
  assert.notEqual(epsXHash('synthetic-চাবি', key), epsXHash('synthetic-key', key));
});

for (const step of steps) test(step + ' request rejects wrong method, endpoint and hash', () => {
  const wrongMethod = request(step); wrongMethod.method = step === 'STATUS' ? 'POST' : 'GET';
  assert.equal(validateEpsRequest(step, wrongMethod, privateContext).code, 'REQUEST_METHOD_INVALID');
  const wrongUrl = request(step); wrongUrl.url = wrongUrl.url.replace('sandboxpgapi.eps.com.bd', 'other.example.com');
  assert.equal(validateEpsRequest(step, wrongUrl, privateContext).accepted, false);
  const wrongHash = request(step); wrongHash.headers['x-hash'] = 'synthetic-invalid-hash';
  assert.equal(validateEpsRequest(step, wrongHash, privateContext).code, 'X_HASH_MISMATCH');
});
test('AUTH body casing, JSON grammar and field set are exact', () => {
  for (const body of [{ username: 'synthetic', password: 'synthetic' }, { userName: 'synthetic' },
    { userName: ' ', password: 'synthetic' }, { userName: 'synthetic', password: 123 },
    { userName: 'synthetic', password: 'synthetic', extra: true }]) {
    const r = request('AUTH'); r.body = JSON.stringify(body); assert.equal(validateEpsRequest('AUTH', r, privateContext).code, 'AUTH_FIELDS_INVALID');
  }
  const duplicate = request('AUTH'); duplicate.body = '{"userName":"synthetic","password":"a","password":"b"}';
  assert.equal(validateEpsRequest('AUTH', duplicate, privateContext).code, 'DUPLICATE_JSON_KEY');
});
for (const key of INITIALIZE_FIELDS) test('INITIALIZE requires exact field ' + key, () => {
  const body = initializeBody(); delete body[key]; const r = request('INITIALIZE'); r.body = JSON.stringify(body);
  assert.equal(validateEpsRequest('INITIALIZE', r, privateContext).code, 'INITIALIZE_FIELDS_INVALID');
});
test('INITIALIZE rejects casing aliases and unsupported optional Postman fields', () => {
  for (const [original, alias] of [['CustomerOrderId', 'customerOrderId'], ['merchantTransactionId', 'merchantTransactonId'], ['customerAddress', 'CustomerAddress'], ['transactionTypeId', 'TransactionTypeId']]) {
    const body = initializeBody(); body[alias] = body[original]; delete body[original]; const r = request('INITIALIZE'); r.body = JSON.stringify(body);
    assert.equal(validateEpsRequest('INITIALIZE', r, privateContext).code, 'INITIALIZE_FIELDS_INVALID');
  }
  const body = { ...initializeBody(), financialEntityId: 0 }; const r = request('INITIALIZE'); r.body = JSON.stringify(body);
  assert.equal(validateEpsRequest('INITIALIZE', r, privateContext).code, 'INITIALIZE_FIELDS_INVALID');
});
for (const transactionTypeId of [10, 2, 3, '1', null]) test('INITIALIZE rejects non-Web-1 transaction type ' + String(transactionTypeId), () => {
  const r = request('INITIALIZE'); r.body = JSON.stringify({ ...initializeBody(), transactionTypeId });
  assert.equal(validateEpsRequest('INITIALIZE', r, privateContext).code, 'WEB_TRANSACTION_TYPE_MUST_BE_1');
});
test('INITIALIZE enforces numeric amount and original identity/amount binding', () => {
  for (const totalAmount of ['100.25', 0, 100.24, true, null]) {
    const r = request('INITIALIZE'); r.body = JSON.stringify({ ...initializeBody(), totalAmount });
    assert.equal(validateEpsRequest('INITIALIZE', r, privateContext).code, 'INITIALIZE_AMOUNT_INVALID');
  }
  for (const delta of [{ merchantTransactionId: '12345678901234567890123' }, { CustomerOrderId: 'SYNTHETIC-OTHER-ORDER' }]) {
    const r = request('INITIALIZE'); r.body = JSON.stringify({ ...initializeBody(), ...delta });
    assert.equal(validateEpsRequest('INITIALIZE', r, privateContext).code, 'INITIALIZE_TRANSACTION_BINDING_INVALID');
  }
});
test('INITIALIZE requires nonempty string customer data and HTTPS callback syntax', () => {
  const empty = request('INITIALIZE'); empty.body = JSON.stringify({ ...initializeBody(), customerEmail: '' });
  assert.equal(validateEpsRequest('INITIALIZE', empty, privateContext).code, 'INITIALIZE_STRING_FIELD_INVALID');
  for (const url of ['http://localhost/eps/success', 'https://127.0.0.1/success', 'https://private.local/success', 'https://synthetic:secret@callbacks.example.com/success', 'https://callbacks.example.com/success#fragment']) {
    const r = request('INITIALIZE'); r.body = JSON.stringify({ ...initializeBody(), successUrl: url });
    assert.equal(validateEpsRequest('INITIALIZE', r, privateContext).code, 'CALLBACK_URL_FORMAT_INVALID');
  }
});
test('HTTP header names are case-insensitive; duplicate cases and header injection are rejected', () => {
  const lower = request('STATUS'); lower.headers = Object.fromEntries(Object.entries(lower.headers).map(([k, v]) => [k.toLowerCase(), v]));
  assert.equal(validateEpsRequest('STATUS', lower, privateContext).accepted, true);
  const duplicate = request('STATUS'); duplicate.headers.authorization = duplicate.headers.Authorization;
  assert.equal(validateEpsRequest('STATUS', duplicate, privateContext).code, 'REQUEST_HEADERS_INVALID');
  for (const delta of [{ Cookie: 'synthetic' }, { 'x-hash': 'synthetic\r\ninjected' }, { 'Content-Type': 'application/x-www-form-urlencoded' }]) {
    const r = request('STATUS'); Object.assign(r.headers, delta); assert.equal(validateEpsRequest('STATUS', r, privateContext).code, 'REQUEST_HEADERS_INVALID');
  }
});
test('Bearer token is required for INITIALIZE/STATUS and forbidden on AUTH', () => {
  const auth = request('AUTH'); auth.headers.Authorization = 'Bearer ' + privateContext.token;
  assert.equal(validateEpsRequest('AUTH', auth, privateContext).code, 'REQUEST_HEADERS_INVALID');
  for (const step of ['INITIALIZE', 'STATUS']) {
    for (const Authorization of ['bearer ' + privateContext.token, 'Bearer synthetic-other-token', '']) {
      const r = request(step); r.headers.Authorization = Authorization;
      assert.equal(validateEpsRequest(step, r, privateContext).code, 'BEARER_TOKEN_BINDING_INVALID');
    }
    const r = request(step); delete r.headers.Authorization;
    assert.equal(validateEpsRequest(step, r, privateContext).code, 'REQUEST_HEADERS_INVALID');
  }
});
test('AUTH hashes username and INITIALIZE/STATUS hash the same exact transaction ID', () => {
  for (const step of steps) {
    const r = request(step); r.headers['x-hash'] = epsXHash(step === 'AUTH' ? identity.merchantTransactionId : 'synthetic-user', privateContext.hashKey);
    assert.equal(validateEpsRequest(step, r, privateContext).code, 'X_HASH_MISMATCH');
    assert.equal(validateEpsRequest(step, request(step), { ...privateContext, hashKey: '' }).code, 'HASH_KEY_CONTEXT_REQUIRED');
  }
});
test('STATUS query name/value, duplicates and absent body are exact', () => {
  for (const suffix of ['?MerchantTransactionId=' + identity.merchantTransactionId, '?merchantTransactionId=1234567890',
    '?merchantTransactionId=' + identity.merchantTransactionId + '&merchantTransactionId=' + identity.merchantTransactionId,
    '?merchantTransactionId=' + identity.merchantTransactionId + '&extra=synthetic', '?merchantTransactionId=' + identity.merchantTransactionId + '#fragment']) {
    const r = request('STATUS'); r.url = r.url.split('?')[0] + suffix;
    assert.equal(validateEpsRequest('STATUS', r, privateContext).code, 'STATUS_URL_OR_QUERY_INVALID');
  }
  const r = request('STATUS'); r.body = '{}';
  assert.equal(validateEpsRequest('STATUS', r, privateContext).code, 'STATUS_REQUEST_BODY_FORBIDDEN');
});
test('STATUS rejects URL-normalization alternatives to the configured canonical endpoint', () => {
  for (const mutate of [url => url.replace('.com.bd/', '.com.bd:443/'),
    url => url.replace('/v1/EPSEngine/', '/v1/other/../EPSEngine/'), url => url.replace('https:', 'http:')]) {
    const r = request('STATUS'); r.url = mutate(r.url);
    assert.equal(validateEpsRequest('STATUS', r, privateContext).code, 'STATUS_URL_OR_QUERY_INVALID');
  }
});
test('transaction IDs remain decimal strings and cannot be coerced from numbers', () => {
  for (const merchantTransactionId of [1234567890, '123456789', '1'.repeat(31), '123456789x', '1234567890 ']) {
    assert.equal(createIdentityRegistry().reserve({ ...identity, merchantTransactionId }).code, 'TRANSACTION_IDENTITY_INVALID');
  }
});
test('new initialization identities reject reuse of either ID without partial reservation', () => {
  const registry = createIdentityRegistry();
  assert.equal(registry.reserve(identity).accepted, true);
  assert.equal(registry.reserve(identity).code, 'TRANSACTION_IDENTITY_ALREADY_USED');
  assert.equal(registry.reserve({ ...identity, customerOrderId: 'SYNTHETIC-ORDER-02' }).code, 'TRANSACTION_IDENTITY_ALREADY_USED');
  const other = { ...identity, merchantTransactionId: '12345678901234567890124' };
  assert.equal(registry.reserve(other).code, 'TRANSACTION_IDENTITY_ALREADY_USED');
  assert.equal(registry.reserve({ ...other, customerOrderId: 'SYNTHETIC-ORDER-02' }).accepted, true);
  // A new process/registry has no global history. This limitation is intentional and documented.
  assert.equal(createIdentityRegistry().reserve(identity).accepted, true);
});
test('request diagnostics never return credential, token, hash or reference values', () => {
  const r = request('STATUS'); r.headers['x-hash'] = 'SYNTHETIC_PRIVATE_HASH_SENTINEL';
  const text = JSON.stringify(validateEpsRequest('STATUS', r, privateContext));
  for (const value of [privateContext.token, privateContext.hashKey, identity.merchantTransactionId, r.headers['x-hash']]) assert.ok(!text.includes(value));
});
