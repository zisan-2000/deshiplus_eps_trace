import { isRecord, own, hasCasingAlias, validToken, MAX_REDIRECT_CHARS,
  MAX_REFERENCE_CHARS, normalizeAmount, expectedTransaction, parseJsonObject } from './contract-utils.mjs';

const names = {
  AUTH: ['token', 'expireDate', 'errorCode', 'errorMessage'],
  INITIALIZE: ['RedirectURL', 'TransactionId', 'ErrorCode', 'ErrorMessage'],
  STATUS: ['MerchantTransactionId', 'TotalAmount', 'Status', 'ErrorCode', 'ErrorMessage']
};
const result = (accepted, outcome, code, paymentVerified = false) => ({ accepted, outcome, code, paymentVerified });
const reject = code => result(false, 'BUSINESS_FAILURE', code);

function errorIssue(payload, step) {
  const codeName = step === 'AUTH' ? 'errorCode' : 'ErrorCode';
  const messageName = step === 'AUTH' ? 'errorMessage' : 'ErrorMessage';
  if (own(payload, codeName)) {
    const code = payload[codeName];
    if (code !== null && typeof code !== 'string' && !(typeof code === 'number' && Number.isFinite(code))) return 'ERROR_FIELD_TYPE_INVALID';
    // Missing/null/empty string/numeric zero match the integration's no-error gate.
    // String "0", whitespace, and any nonzero code are errors, never success aliases.
    if (code !== null && code !== '' && code !== 0) return 'GATEWAY_ERROR_REPORTED';
  }
  if (own(payload, messageName)) {
    const message = payload[messageName];
    if (message !== null && typeof message !== 'string') return 'ERROR_FIELD_TYPE_INVALID';
    if (message !== null && message !== '') return 'GATEWAY_ERROR_REPORTED';
  }
  return null;
}
function validRedirect(value) {
  if (typeof value !== 'string' || !value || value.length > MAX_REDIRECT_CHARS ||
      value.trim() !== value || /[\x00-\x20\x7f]/.test(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.hash &&
      (!url.port || url.port === '443') && (url.hostname === 'eps.com.bd' || url.hostname.endsWith('.eps.com.bd'));
  } catch { return false; }
}

// These return safe fixed codes only, never tokens, IDs, redirect URLs or messages.
export function validateEpsPayload(step, payload, context = {}) {
  if (!own(names, step)) return reject('UNKNOWN_EPS_STEP');
  if (!isRecord(payload)) return reject('JSON_OBJECT_REQUIRED');
  if (hasCasingAlias(payload, names[step])) return reject('RESPONSE_FIELD_CASING_INVALID');
  const error = errorIssue(payload, step);
  if (error) return reject(error);
  if (step === 'AUTH') {
    if (!own(payload, 'token') || !validToken(payload.token)) return reject('AUTH_TOKEN_INVALID');
    return result(true, 'SUCCESS', 'AUTH_ACCEPTED');
  }
  if (step === 'INITIALIZE') {
    if (!own(payload, 'RedirectURL') || !validRedirect(payload.RedirectURL)) return reject('INITIALIZE_REDIRECT_INVALID');
    if (own(payload, 'TransactionId') && payload.TransactionId !== null &&
        (typeof payload.TransactionId !== 'string' || !payload.TransactionId.trim() ||
          payload.TransactionId.length > MAX_REFERENCE_CHARS || /[\x00-\x1f\x7f]/.test(payload.TransactionId))) {
      return reject('INITIALIZE_TRANSACTION_ID_INVALID');
    }
    return result(true, 'SUCCESS', 'INITIALIZE_ACCEPTED');
  }
  const expected = expectedTransaction(context);
  if (!expected) return reject('EXPECTED_TRANSACTION_CONTEXT_REQUIRED');
  if (!own(payload, 'MerchantTransactionId') || payload.MerchantTransactionId !== expected.merchantTransactionId) return reject('STATUS_TRANSACTION_MISMATCH');
  if (!own(payload, 'TotalAmount') || normalizeAmount(payload.TotalAmount) !== expected.amount) return reject('STATUS_AMOUNT_MISMATCH');
  if (!own(payload, 'Status') || typeof payload.Status !== 'string' || !payload.Status.trim()) return reject('STATUS_FIELD_INVALID');
  if (payload.Status !== 'Success') return result(false, 'PENDING', 'STATUS_NOT_CONFIRMED');
  return result(true, 'SUCCESS', 'STATUS_SUCCESS_CONFIRMED', true);
}

export function validateEpsResponse(step, { httpStatus, body } = {}, context = {}) {
  if (!own(names, step)) return reject('UNKNOWN_EPS_STEP');
  if (!Number.isInteger(httpStatus)) return result(false, 'HTTP_FAILURE', 'HTTP_STATUS_INVALID');
  if (httpStatus < 200 || httpStatus >= 300) return result(false, 'HTTP_FAILURE', 'HTTP_STATUS_REJECTED');
  const parsed = parseJsonObject(body);
  if (parsed.code) return result(false, 'RESPONSE_FAILURE', parsed.code);
  return validateEpsPayload(step, parsed.value, context);
}
