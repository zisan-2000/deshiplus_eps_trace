import { timingSafeEqual } from 'node:crypto';
import { ENDPOINTS } from './eps-contract.mjs';
import { epsXHash } from './signing.mjs';
import { callbackIsolationIssue } from './execution-safety.mjs';
import { isRecord, own, nonBlank, validToken, validMerchantTransactionId, validCustomerOrderId,
  normalizeAmount, expectedTransaction, parseJsonObject, publicHttps } from './contract-utils.mjs';

export const INITIALIZE_FIELDS = Object.freeze([
  'merchantId', 'storeId', 'CustomerOrderId', 'merchantTransactionId', 'transactionTypeId', 'totalAmount',
  'successUrl', 'failUrl', 'cancelUrl', 'customerName', 'customerEmail', 'customerAddress',
  'customerCity', 'customerState', 'customerPostcode', 'customerCountry', 'customerPhone', 'productName'
]);
const keysEqual = (object, keys) => isRecord(object) && Object.keys(object).length === keys.length && keys.every(key => own(object, key));
const pass = code => ({ accepted: true, code });
const fail = code => ({ accepted: false, code });

export function validateEpsRequest(step, request, context = {}) {
  if (!own(ENDPOINTS, step)) return fail('UNKNOWN_EPS_STEP');
  if (!isRecord(request) || !isRecord(context)) return fail('REQUEST_OBJECT_REQUIRED');
  if (request.method !== (step === 'STATUS' ? 'GET' : 'POST')) return fail('REQUEST_METHOD_INVALID');
  if (!isRecord(request.headers)) return fail('REQUEST_HEADERS_INVALID');
  const headers = {};
  for (const [key, value] of Object.entries(request.headers)) {
    const lower = key.toLowerCase();
    if (own(headers, lower) || typeof value !== 'string' || /[\x00-\x1f\x7f]/.test(value)) return fail('REQUEST_HEADERS_INVALID');
    Object.defineProperty(headers, lower, { value, enumerable: true });
  }
  const expectedHeaders = ['content-type', 'x-hash', ...(step === 'AUTH' ? [] : ['authorization'])];
  if (!keysEqual(headers, expectedHeaders) || headers['content-type'] !== 'application/json') return fail('REQUEST_HEADERS_INVALID');
  if (!nonBlank(context.hashKey)) return fail('HASH_KEY_CONTEXT_REQUIRED');
  if (step !== 'AUTH' && (!validToken(context.token) || headers.authorization !== 'Bearer ' + context.token)) return fail('BEARER_TOKEN_BINDING_INVALID');
  let hashInput;
  if (step === 'STATUS') {
    const expected = expectedTransaction(context);
    if (!expected) return fail('EXPECTED_TRANSACTION_CONTEXT_REQUIRED');
    try {
      if (typeof request.url !== 'string' || request.url.trim() !== request.url ||
          request.url.split('?')[0] !== ENDPOINTS.STATUS) throw new Error();
      const url = new URL(request.url);
      if (url.origin + url.pathname !== ENDPOINTS.STATUS || url.username || url.password || url.hash ||
          url.searchParams.size !== 1 || url.searchParams.getAll('merchantTransactionId').length !== 1 ||
          url.searchParams.get('merchantTransactionId') !== expected.merchantTransactionId) throw new Error();
      hashInput = expected.merchantTransactionId;
    } catch { return fail('STATUS_URL_OR_QUERY_INVALID'); }
    if (request.body !== null) return fail('STATUS_REQUEST_BODY_FORBIDDEN');
  } else {
    if (request.url !== ENDPOINTS[step]) return fail('REQUEST_ENDPOINT_INVALID');
    const parsed = parseJsonObject(request.body);
    if (parsed.code) return fail(parsed.code);
    const body = parsed.value;
    if (step === 'AUTH') {
      if (!keysEqual(body, ['userName', 'password']) || !nonBlank(body.userName) || !nonBlank(body.password)) return fail('AUTH_FIELDS_INVALID');
      hashInput = body.userName;
    } else {
      if (!keysEqual(body, INITIALIZE_FIELDS)) return fail('INITIALIZE_FIELDS_INVALID');
      if (body.transactionTypeId !== 1) return fail('WEB_TRANSACTION_TYPE_MUST_BE_1');
      if (INITIALIZE_FIELDS.filter(key => !['transactionTypeId', 'totalAmount'].includes(key)).some(key => !nonBlank(body[key]))) return fail('INITIALIZE_STRING_FIELD_INVALID');
      const expected = expectedTransaction(context);
      if (!expected || !validCustomerOrderId(context.customerOrderId)) return fail('EXPECTED_TRANSACTION_CONTEXT_REQUIRED');
      if (!validMerchantTransactionId(body.merchantTransactionId) || body.merchantTransactionId !== expected.merchantTransactionId ||
          !validCustomerOrderId(body.CustomerOrderId) || body.CustomerOrderId !== context.customerOrderId) return fail('INITIALIZE_TRANSACTION_BINDING_INVALID');
      if (typeof body.totalAmount !== 'number' || normalizeAmount(body.totalAmount) !== expected.amount) return fail('INITIALIZE_AMOUNT_INVALID');
      if (['successUrl', 'failUrl', 'cancelUrl'].some(key => !publicHttps(body[key]))) return fail('CALLBACK_URL_FORMAT_INVALID');
      const isolation = callbackIsolationIssue(body, context);
      if (isolation) return fail(isolation);
      hashInput = body.merchantTransactionId;
    }
  }
  const actual = Buffer.from(headers['x-hash'], 'utf8');
  const expectedHash = Buffer.from(epsXHash(hashInput, context.hashKey), 'utf8');
  if (actual.length !== expectedHash.length || !timingSafeEqual(actual, expectedHash)) return fail('X_HASH_MISMATCH');
  return pass('REQUEST_CONTRACT_ACCEPTED');
}

// Detects reuse only within this registry's lifetime. It is not a merchant-wide ledger.
// Reserve only for a new initialization, never for a STATUS query. No auto-release/retry.
export function createIdentityRegistry() {
  const transactions = new Set(), orders = new Set();
  return Object.freeze({
    reserve(identity) {
      if (!isRecord(identity) || !validMerchantTransactionId(identity.merchantTransactionId) || !validCustomerOrderId(identity.customerOrderId)) return fail('TRANSACTION_IDENTITY_INVALID');
      if (transactions.has(identity.merchantTransactionId) || orders.has(identity.customerOrderId)) return fail('TRANSACTION_IDENTITY_ALREADY_USED');
      transactions.add(identity.merchantTransactionId); orders.add(identity.customerOrderId);
      return pass('TRANSACTION_IDENTITY_RESERVED');
    }
  });
}
