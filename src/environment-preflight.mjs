import { epsXHash } from './signing.mjs';
import { nonBlank, validCustomerOrderId, validMerchantTransactionId, normalizeAmount } from './contract-utils.mjs';

// Fixed local-only synthetic profile. Gateway acceptance is not implied.
export const SYNTHETIC_CUSTOMER_ENV = Object.freeze({
  EPS_TRACE_CUSTOMER_NAME: 'EPS Diagnostic Synthetic Customer',
  EPS_TRACE_CUSTOMER_EMAIL: 'eps-diagnostic@example.com',
  EPS_TRACE_CUSTOMER_ADDRESS: 'Synthetic Sandbox Address',
  EPS_TRACE_CUSTOMER_CITY: 'Synthetic City', EPS_TRACE_CUSTOMER_STATE: 'Synthetic State',
  EPS_TRACE_CUSTOMER_POSTCODE: '0000', EPS_TRACE_CUSTOMER_COUNTRY: 'Bangladesh',
  EPS_TRACE_CUSTOMER_PHONE: '00000000000', EPS_TRACE_PRODUCT_NAME: 'Synthetic diagnostic item'
});
const credentialNames = ['EPS_USERNAME', 'EPS_PASSWORD', 'EPS_HASH_KEY', 'EPS_MERCHANT_ID', 'EPS_STORE_ID'];
const badUnicode = value => /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value);
export function hasStaticToken(environment) {
  return Object.entries(environment).some(([key, value]) => /^EPS_(?:(?:AUTH|ACCESS|BEARER)_)?(?:TOKEN|JWT)$/i.test(key) && nonBlank(value));
}
export function hmacSelfTest() {
  const expectedHex = '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
    'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854';
  return epsXHash('Hi There', '\x0b'.repeat(20)) === Buffer.from(expectedHex, 'hex').toString('base64');
}

// Step 5 preparation policy, additional to the underlying EPS request contract.
// No process.env default, files, network, hashes or sensitive values in results.
export function validatePreparationDetails(environment) {
  const issues = [];
  for (const name of credentialNames) {
    const value = environment[name];
    if (nonBlank(value) && (/[\x00\r\n]/.test(value) || badUnicode(value))) issues.push('ENV_INVALID:' + name);
  }
  for (const [name, expected] of Object.entries(SYNTHETIC_CUSTOMER_ENV)) {
    if (nonBlank(environment[name]) && environment[name] !== expected) issues.push('ENV_INVALID:' + name);
  }
  const merchantId = environment.EPS_TRACE_MERCHANT_TRANSACTION_ID;
  const orderId = environment.EPS_TRACE_CUSTOMER_ORDER_ID;
  if (nonBlank(orderId) && !validCustomerOrderId(orderId)) issues.push('ENV_INVALID:EPS_TRACE_CUSTOMER_ORDER_ID');
  if (nonBlank(merchantId) && validMerchantTransactionId(merchantId) && !/^[0-9]{23}$/.test(merchantId)) issues.push('PREPARATION_ID_FORMAT_INVALID');
  if (nonBlank(orderId) && nonBlank(merchantId) &&
      (!/^DPEPS-[0-9]{23}-[a-f0-9]{16}$/.test(orderId) || !orderId.startsWith('DPEPS-' + merchantId + '-'))) {
    issues.push('PREPARATION_ID_CORRELATION_INVALID');
  }
  const amount = environment.EPS_TRACE_AMOUNT;
  if (nonBlank(amount) && normalizeAmount(amount) && normalizeAmount(amount) !== '0.00' && amount !== normalizeAmount(amount)) issues.push('PREPARATION_AMOUNT_MUST_BE_CANONICAL');
  if (hasStaticToken(environment)) issues.push('STATIC_EPS_TOKEN_FORBIDDEN');
  if (!hmacSelfTest()) issues.push('HMAC_SHA512_SELF_TEST_FAILED');
  if (credentialNames.every(name => nonBlank(environment[name])) && validMerchantTransactionId(merchantId) &&
      !issues.some(code => code.startsWith('ENV_INVALID:EPS_') && credentialNames.some(name => code.endsWith(name)))) {
    try {
      for (const input of [environment.EPS_USERNAME, merchantId]) {
        let hash = epsXHash(input, environment.EPS_HASH_KEY);
        if (!/^[A-Za-z0-9+/]{86}==$/.test(hash) || Buffer.from(hash, 'base64').length !== 64) issues.push('HMAC_SIGNING_REQUIREMENTS_INVALID');
        hash = null;
      }
    } catch { issues.push('HMAC_SIGNING_REQUIREMENTS_INVALID'); }
  }
  return [...new Set(issues)];
}
