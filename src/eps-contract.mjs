// Request plans only. This module has no HTTP, database or ecommerce imports.
import { SAFETY_ENV_NAMES, createSafetyPolicy } from './execution-safety.mjs';
export const CONTRACT = 'EPS_MERCHANT_V4_SANDBOX';
export const STAGE = 'STEP_7C_AUTH_ONLY_PREPARED';
export const ENDPOINTS = Object.freeze({
  AUTH: 'https://sandboxpgapi.eps.com.bd/v1/Auth/GetToken',
  INITIALIZE: 'https://sandboxpgapi.eps.com.bd/v1/EPSEngine/InitializeEPS',
  STATUS: 'https://sandboxpgapi.eps.com.bd/v1/EPSEngine/CheckMerchantTransactionStatus'
});
export const CREDENTIAL_ENV_NAMES = Object.freeze([
  'EPS_USERNAME', 'EPS_PASSWORD', 'EPS_HASH_KEY', 'EPS_MERCHANT_ID', 'EPS_STORE_ID'
]);
export const INPUT_ENV_NAMES = Object.freeze([
  'EPS_TRACE_CUSTOMER_ORDER_ID', 'EPS_TRACE_MERCHANT_TRANSACTION_ID', 'EPS_TRACE_AMOUNT',
  'EPS_TRACE_SUCCESS_URL', 'EPS_TRACE_FAIL_URL', 'EPS_TRACE_CANCEL_URL',
  'EPS_TRACE_CUSTOMER_NAME', 'EPS_TRACE_CUSTOMER_EMAIL', 'EPS_TRACE_CUSTOMER_ADDRESS',
  'EPS_TRACE_CUSTOMER_CITY', 'EPS_TRACE_CUSTOMER_STATE', 'EPS_TRACE_CUSTOMER_POSTCODE',
  'EPS_TRACE_CUSTOMER_COUNTRY', 'EPS_TRACE_CUSTOMER_PHONE', 'EPS_TRACE_PRODUCT_NAME'
]);
export const REQUIRED_ENV_NAMES = Object.freeze(['EPS_ENV', ...CREDENTIAL_ENV_NAMES, ...INPUT_ENV_NAMES, ...SAFETY_ENV_NAMES]);

const ref = (env, type = 'string') => ({ env, type });
const hashPlan = inputEnv => ({
  header: 'x-hash', algorithm: 'HMAC-SHA512', keyEnv: 'EPS_HASH_KEY', inputEnv,
  keyEncoding: 'utf8', inputEncoding: 'utf8', outputEncoding: 'base64'
});
const headers = authenticated => ({
  'Content-Type': 'application/json',
  ...(authenticated ? { Authorization: { scheme: 'Bearer', variable: 'EPS_TOKEN' } } : {})
});

export function requestPlans() {
  return [
    {
      name: 'AUTH', method: 'POST', url: ENDPOINTS.AUTH,
      headers: headers(false), signing: hashPlan('EPS_USERNAME'),
      body: { userName: ref('EPS_USERNAME'), password: ref('EPS_PASSWORD') },
      query: {}, extract: { EPS_TOKEN: 'token' }, optionalExtract: {}, observe: []
    },
    {
      name: 'INITIALIZE', method: 'POST', url: ENDPOINTS.INITIALIZE,
      headers: headers(true), signing: hashPlan('EPS_TRACE_MERCHANT_TRANSACTION_ID'),
      body: {
        merchantId: ref('EPS_MERCHANT_ID'), storeId: ref('EPS_STORE_ID'),
        CustomerOrderId: ref('EPS_TRACE_CUSTOMER_ORDER_ID'),
        merchantTransactionId: ref('EPS_TRACE_MERCHANT_TRANSACTION_ID'),
        transactionTypeId: 1, totalAmount: ref('EPS_TRACE_AMOUNT', 'number'),
        successUrl: ref('EPS_TRACE_SUCCESS_URL'), failUrl: ref('EPS_TRACE_FAIL_URL'),
        cancelUrl: ref('EPS_TRACE_CANCEL_URL'), customerName: ref('EPS_TRACE_CUSTOMER_NAME'),
        customerEmail: ref('EPS_TRACE_CUSTOMER_EMAIL'), customerAddress: ref('EPS_TRACE_CUSTOMER_ADDRESS'),
        customerCity: ref('EPS_TRACE_CUSTOMER_CITY'), customerState: ref('EPS_TRACE_CUSTOMER_STATE'),
        customerPostcode: ref('EPS_TRACE_CUSTOMER_POSTCODE'), customerCountry: ref('EPS_TRACE_CUSTOMER_COUNTRY'),
        customerPhone: ref('EPS_TRACE_CUSTOMER_PHONE'), productName: ref('EPS_TRACE_PRODUCT_NAME')
      },
      query: {}, extract: { EPS_REDIRECT_URL: 'RedirectURL' },
      optionalExtract: { EPS_TRANSACTION_ID: 'TransactionId' }, observe: []
    },
    {
      name: 'STATUS', method: 'GET', url: ENDPOINTS.STATUS,
      headers: headers(true), signing: hashPlan('EPS_TRACE_MERCHANT_TRANSACTION_ID'),
      body: null, query: { merchantTransactionId: ref('EPS_TRACE_MERCHANT_TRANSACTION_ID') },
      extract: {}, optionalExtract: {}, observe: ['Status']
    }
  ];
}

export function createTemplate() {
  return {
    contract: CONTRACT, stage: STAGE, environment: 'sandbox', profile: 'template',
    execution: { networkEnabled: false, paymentRequestsEnabled: false, callbacksEnabled: false, automaticRetries: 0 },
    session: { name: 'EPS_SANDBOX_STEP_7B_PREPARATION', outputRoot: './evidence/eps-sandbox' },
    capture: {
      enabled: false, interface: '5', tsharkPath: 'C:\\Program Files\\Wireshark\\tshark.exe',
      captureFilter: 'tcp port 443 and host sandboxpgapi.eps.com.bd',
      preservePcap: false, format: 'pcapng', fileName: 'session.pcapng',
      readinessRequired: true, readinessTimeoutMs: 8000, abortOnFailure: true, tlsKeyLoggingEnabled: false
    },
    network: { timeoutMs: 20000, maxResponseBytes: 32768, rejectUnauthorized: true, followRedirects: false },
    evidence: {
      includeRequestHeaders: false, includeResponseHeaders: false,
      includeRequestBody: false, includeResponseBody: false, hashBodies: true,
      maskKeys: [
        'authorization', 'x-hash', 'username', 'password', 'hashkey', 'merchantid', 'storeid',
        'token', 'jwt', 'secret', 'cookie', 'set-cookie', 'merchanttransactionid', 'customerorderid',
        'transactionid', 'totalamount', 'redirecturl', 'successurl', 'failurl', 'cancelurl',
        'customername', 'customeremail', 'customeraddress', 'customeraddress2', 'customercity',
        'customerstate', 'customerpostcode', 'customercountry', 'customerphone', 'customerid',
        'shipmentname', 'shipmentaddress', 'shipmentaddress2', 'shipmentcity', 'shipmentstate',
        'shipmentpostcode', 'shipmentcountry', 'productname', 'productlist',
        'valuea', 'valueb', 'valuec', 'valued', 'attempt', 'state', 'errormessage'
      ]
    },
    safety: createSafetyPolicy(), steps: requestPlans()
  };
}

export function createLocalConfig() {
  const cfg = createTemplate();
  cfg.profile = 'standalone-local';
  cfg.session.name = 'EPS_SANDBOX_LOCAL_STEP_7B';
  cfg.capture.preservePcap = true;
  return cfg;
}
