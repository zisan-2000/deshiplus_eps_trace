import { isRecord, publicHttps } from './contract-utils.mjs';

export const CALLBACK_PATHS = Object.freeze({
  successUrl: '/eps-trace/success', failUrl: '/eps-trace/fail', cancelUrl: '/eps-trace/cancel'
});
export const SAFETY_ENV_NAMES = Object.freeze(['EPS_TRACE_CALLBACK_ORIGIN', 'EPS_TRACE_ECOMMERCE_ORIGINS']);
export const EXECUTION_BLOCKERS = Object.freeze([
  'LIVE_EPS_TRANSPORT_EXECUTION_NOT_APPROVED', 'PRIVATE_SANDBOX_INPUTS_NOT_VERIFIED',
  'LIVE_ATTEMPT_LEDGER_SCOPE_NOT_APPROVED', 'HOSTED_PAYMENT_PROCEDURE_UNCONFIRMED',
  'ISOLATED_CALLBACK_RECEIVER_OWNERSHIP_UNCONFIRMED', 'CALLBACK_DELIVERY_CONTRACT_UNCONFIRMED',
  'ECOMMERCE_ORIGIN_DENYLIST_NOT_INDEPENDENTLY_VERIFIED',
  'STATUS_POLLING_RETRY_POLICY_UNCONFIRMED', 'FRESH_CAPTURE_READINESS_REQUIRED'
]);

export function createSafetyPolicy() {
  return {
    endpointPolicy: 'exact-sandbox-step-urls-only',
    environmentPreparation: { source: 'hidden-prompts-only', storage: 'process-only',
      customerData: 'fixed-synthetic-profile', validation: 'offline-network-guard-required',
      callbackAvailabilityRequiredBeforeCredentials: true, existingIdentityOverwriteAllowed: false },
    callbackIsolation: {
      origin: { env: 'EPS_TRACE_CALLBACK_ORIGIN', type: 'https-origin' },
      ecommerceOrigins: { env: 'EPS_TRACE_ECOMMERCE_ORIGINS', type: 'json-array-of-origins' },
      forbidSharedHostname: true, paths: { ...CALLBACK_PATHS },
      maxUrlChars: 4096, maxEcommerceOrigins: 32,
      queryPolicy: 'forbidden-until-contract-reviewed', redirectsAllowed: false,
      receiverOwnership: 'UNCONFIRMED'
    },
    attemptTracking: {
      requiredBeforeInitialize: true, restartSafeRequired: true, atomicReservationRequired: true,
      storage: 'private-atomic-journal-prepared-for-account-scoped-live-attempts',
      scope: ['sandbox', 'merchantAccountFingerprint', 'storeFingerprint'],
      uniqueFields: ['merchantTransactionId', 'CustomerOrderId'],
      persistMinimum: ['merchantAccountFingerprint', 'storeFingerprint', 'merchantTransactionId',
        'CustomerOrderId', 'amount', 'currency', 'phase', 'requestFingerprint', 'updatedAt'],
      ownerOnlyAccessRequired: true, protectedStorageRequired: true,
      persistCredentials: false, persistTokens: false, persistCustomerData: false, persistSignedUrls: false,
      uncertainInitialization: 'block-new-initialization-and-require-reconciliation',
      statusBinding: 'original-account-id-and-amount', automaticRestartResume: false
    },
    hostedPayment: { manualGateRequiredBeforeStatus: true, procedure: 'UNCONFIRMED' },
    statusRetry: { policy: 'UNCONFIRMED', automaticRetries: 0 },
    blockers: [...EXECUTION_BLOCKERS]
  };
}

function originDetails(value) {
  if (!publicHttps(value) || value.length > 4096 || value.includes('\\')) return null;
  try {
    const url = new URL(value);
    if (url.pathname !== '/' || url.search || url.hash) return null;
    url.hostname = url.hostname.replace(/\.$/, '');
    return { origin: url.origin, hostname: url.hostname.toLowerCase() };
  } catch { return null; }
}

// Known ecommerce hosts and all app callback routes are blocked. Completeness of
// the supplied denylist and isolated receiver ownership still need external review.
// This function does not resolve DNS, follow redirects, send callbacks or read .env.
export function callbackIsolationIssue(callbacks, context = {}) {
  if (!isRecord(callbacks) || !isRecord(context)) return 'CALLBACK_ISOLATION_CONTEXT_REQUIRED';
  const isolated = originDetails(context.callbackOrigin);
  if (!isolated) return 'ISOLATED_CALLBACK_ORIGIN_REQUIRED';
  if (!Array.isArray(context.ecommerceOrigins) || context.ecommerceOrigins.length < 1 || context.ecommerceOrigins.length > 32) return 'ECOMMERCE_ORIGIN_DENYLIST_REQUIRED';
  const denied = context.ecommerceOrigins.map(originDetails);
  if (denied.some(value => !value) || new Set(denied.map(value => value?.origin)).size !== denied.length) return 'ECOMMERCE_ORIGIN_DENYLIST_INVALID';
  const deniedHosts = new Set(denied.map(value => value.hostname));
  if (deniedHosts.has(isolated.hostname)) return 'ECOMMERCE_CALLBACK_TARGET_FORBIDDEN';
  for (const [field, expectedPath] of Object.entries(CALLBACK_PATHS)) {
    const value = callbacks[field];
    if (!publicHttps(value) || value.length > 4096 || value.includes('\\')) return 'CALLBACK_URL_FORMAT_INVALID';
    const url = new URL(value);
    const hostname = url.hostname.replace(/\.$/, '').toLowerCase();
    if (deniedHosts.has(hostname)) return 'ECOMMERCE_CALLBACK_TARGET_FORBIDDEN';
    let decodedPath;
    try { decodedPath = decodeURIComponent(decodeURIComponent(url.pathname)).replace(/\/+/g, '/').toLowerCase(); }
    catch { return 'CALLBACK_PATH_INVALID'; }
    if (/^\/api\/(eps|aibl-wallet)(\/|$)/.test(decodedPath)) return 'ECOMMERCE_CALLBACK_ROUTE_FORBIDDEN';
    url.hostname = hostname;
    if (url.origin !== isolated.origin || (url.port && url.port !== '443')) return 'CALLBACK_ORIGIN_MISMATCH';
    if (url.pathname !== expectedPath || url.search || url.hash) return 'CALLBACK_PATH_OR_QUERY_FORBIDDEN';
  }
  return null;
}

// Structural/environment PASS cannot self-authorize payment execution.
export function executionSafetySummary() {
  return { executionReady: false, blockers: [...EXECUTION_BLOCKERS] };
}
