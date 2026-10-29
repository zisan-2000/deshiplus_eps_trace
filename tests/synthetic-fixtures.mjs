import { ENDPOINTS } from '../src/eps-contract.mjs';
import { epsXHash } from '../src/signing.mjs';
import { SYNTHETIC_CUSTOMER_ENV } from '../src/environment-preflight.mjs';

export function syntheticEnvironment() {
  return { ...SYNTHETIC_CUSTOMER_ENV, EPS_ENV: 'sandbox', EPS_USERNAME: 'synthetic-user',
    EPS_PASSWORD: 'synthetic-test-password', EPS_HASH_KEY: 'synthetic-utf8-hash-key',
    EPS_MERCHANT_ID: 'synthetic-merchant', EPS_STORE_ID: 'synthetic-store',
    EPS_TRACE_CUSTOMER_ORDER_ID: 'DPEPS-' + identity.merchantTransactionId + '-0123456789abcdef',
    EPS_TRACE_MERCHANT_TRANSACTION_ID: identity.merchantTransactionId, EPS_TRACE_AMOUNT: identity.amount,
    EPS_TRACE_CALLBACK_ORIGIN: privateContext.callbackOrigin, EPS_TRACE_ECOMMERCE_ORIGINS: JSON.stringify(privateContext.ecommerceOrigins),
    EPS_TRACE_SUCCESS_URL: privateContext.callbackOrigin + '/eps-trace/success',
    EPS_TRACE_FAIL_URL: privateContext.callbackOrigin + '/eps-trace/fail',
    EPS_TRACE_CANCEL_URL: privateContext.callbackOrigin + '/eps-trace/cancel' };
}

// Deliberately synthetic. No values are copied from Postman, .env or a real order.
export const identity = Object.freeze({
  merchantTransactionId: '00000000001234567890123', customerOrderId: 'SYNTHETIC-ORDER-01', amount: '100.25'
});
export const privateContext = Object.freeze({ ...identity, hashKey: 'synthetic-utf8-hash-key', token: 'synthetic.opaque.token',
  callbackOrigin: 'https://callbacks.example.com', ecommerceOrigins: Object.freeze(['https://shop.example.com']) });
export function payload(step) {
  if (step === 'AUTH') return { token: privateContext.token, errorCode: null, errorMessage: null };
  if (step === 'INITIALIZE') return { RedirectURL: 'https://sandbox.eps.com.bd/checkout?reference=synthetic',
    TransactionId: 'SYNTHETIC-EPS-REFERENCE', ErrorCode: null, ErrorMessage: null };
  return { MerchantTransactionId: identity.merchantTransactionId, TotalAmount: 100.25,
    Status: 'Success', ErrorCode: null, ErrorMessage: null };
}
export function initializeBody() {
  return {
    merchantId: 'synthetic-merchant', storeId: 'synthetic-store', CustomerOrderId: identity.customerOrderId,
    merchantTransactionId: identity.merchantTransactionId, transactionTypeId: 1, totalAmount: 100.25,
    successUrl: 'https://callbacks.example.com/eps-trace/success', failUrl: 'https://callbacks.example.com/eps-trace/fail',
    cancelUrl: 'https://callbacks.example.com/eps-trace/cancel', customerName: 'Synthetic User',
    customerEmail: 'synthetic@example.com', customerAddress: 'Synthetic address', customerCity: 'Synthetic city',
    customerState: 'Synthetic state', customerPostcode: '0000', customerCountry: 'Bangladesh',
    customerPhone: '00000000000', productName: 'Synthetic product'
  };
}
export function request(step) {
  const auth = step === 'AUTH';
  const body = auth ? { userName: 'synthetic-user', password: 'synthetic-test-password' } : initializeBody();
  return {
    method: step === 'STATUS' ? 'GET' : 'POST',
    url: ENDPOINTS[step] + (step === 'STATUS' ? '?merchantTransactionId=' + identity.merchantTransactionId : ''),
    headers: { 'Content-Type': 'application/json',
      'x-hash': epsXHash(auth ? body.userName : identity.merchantTransactionId, privateContext.hashKey),
      ...(auth ? {} : { Authorization: 'Bearer ' + privateContext.token }) },
    body: step === 'STATUS' ? null : JSON.stringify(body)
  };
}
