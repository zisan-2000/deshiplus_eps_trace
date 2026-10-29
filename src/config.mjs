import fs from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { fileURLToPath } from 'node:url';
import { CONTRACT, STAGE, REQUIRED_ENV_NAMES, createTemplate, requestPlans } from './eps-contract.mjs';
import { publicHttps, normalizeAmount, validMerchantTransactionId, parseJsonObject } from './contract-utils.mjs';
import { callbackIsolationIssue } from './execution-safety.mjs';
import { validatePreparationDetails } from './environment-preflight.mjs';

export const EXAMPLE_CONFIG = fileURLToPath(new URL('../config.eps.sandbox.example.json', import.meta.url));
export const DEFAULT_CONFIG = fileURLToPath(new URL('../config.eps.sandbox.local.json', import.meta.url));
const sameKeys = (a, b) => isDeepStrictEqual(Object.keys(a || {}).sort(), Object.keys(b).sort());
export function loadConfig(file = DEFAULT_CONFIG) {
  try {
    const parsed = parseJsonObject(fs.readFileSync(file));
    if (parsed.code) throw new Error();
    return parsed.value;
  }
  catch { throw new Error('CONFIG_READ_OR_PARSE_FAILED'); }
}

export function validateConfig(cfg) {
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return ['CONFIG_OBJECT_REQUIRED'];
  const expected = createTemplate();
  const issues = [];
  if (!sameKeys(cfg, expected)) issues.push('CONFIG_KEYS_INVALID');
  if (!['template', 'standalone-local'].includes(cfg.profile)) issues.push('CONFIG_PROFILE_INVALID');
  if (cfg.contract !== CONTRACT || cfg.stage !== STAGE || cfg.environment !== 'sandbox') issues.push('OFFLINE_SANDBOX_CONTRACT_REQUIRED');
  if (!isDeepStrictEqual(cfg.execution, expected.execution)) issues.push('ALL_NETWORK_EXECUTION_MUST_REMAIN_DISABLED');
  if (!isDeepStrictEqual(cfg.network, expected.network)) issues.push('NETWORK_SAFETY_PLAN_INVALID');
  if (!isDeepStrictEqual(cfg.evidence, expected.evidence)) issues.push('SAFE_EVIDENCE_PLAN_REQUIRED');
  if (!isDeepStrictEqual(cfg.safety, expected.safety)) issues.push('STANDALONE_EXECUTION_SAFETY_POLICY_REQUIRED');
  if (!sameKeys(cfg.session, expected.session) || typeof cfg.session?.name !== 'string' ||
      !/^[A-Za-z0-9_-]{1,80}$/.test(cfg.session.name) || cfg.session?.outputRoot !== expected.session.outputRoot) issues.push('SESSION_PLAN_INVALID');
  const capture = cfg.capture;
  if (!sameKeys(capture, expected.capture) || capture?.enabled !== false || capture?.preservePcap !== (cfg.profile === 'standalone-local') ||
      capture?.format !== 'pcapng' || capture?.fileName !== 'session.pcapng' || capture?.readinessRequired !== true ||
      capture?.readinessTimeoutMs !== 8000 || capture?.abortOnFailure !== true ||
      capture?.tlsKeyLoggingEnabled !== false || capture?.interface !== '5' ||
      typeof capture?.tsharkPath !== 'string' || !capture.tsharkPath.trim() || capture?.captureFilter !== expected.capture.captureFilter) {
    issues.push('OFFLINE_CAPTURE_MUST_REMAIN_DISABLED');
  }
  const plans = requestPlans();
  if (!Array.isArray(cfg.steps) || cfg.steps.length !== plans.length) issues.push('EXACT_THREE_STEP_PLAN_REQUIRED');
  else for (let i = 0; i < plans.length; i++) {
    const step = cfg.steps[i], plan = plans[i];
    if (!step || typeof step !== 'object' || Array.isArray(step)) { issues.push('REQUEST_PLAN_INVALID'); continue; }
    if (!sameKeys(step, plan) || step.name !== plan.name) issues.push('EXACT_STEP_SEQUENCE_REQUIRED');
    if (step.method !== plan.method || step.url !== plan.url) issues.push(plan.name + '_METHOD_OR_ENDPOINT_INVALID');
    if (!isDeepStrictEqual(step.headers, plan.headers)) issues.push(plan.name + '_HEADER_PLAN_INVALID');
    if (!isDeepStrictEqual(step.signing, plan.signing)) issues.push(plan.name + '_HASH_PLAN_INVALID');
    if (!isDeepStrictEqual(step.body, plan.body) || !isDeepStrictEqual(step.query, plan.query)) issues.push(plan.name + '_FIELD_BINDINGS_INVALID');
    if (plan.name === 'INITIALIZE' && step.body?.transactionTypeId !== 1) issues.push('WEB_TRANSACTION_TYPE_MUST_BE_1');
    if (!isDeepStrictEqual(step.extract, plan.extract) || !isDeepStrictEqual(step.optionalExtract, plan.optionalExtract) ||
        !isDeepStrictEqual(step.observe, plan.observe)) issues.push(plan.name + '_RESPONSE_PLAN_INVALID');
  }
  return [...new Set(issues)];
}

// Only fixed environment variable names and issue codes are returned; values stay private.
export function validateEnvironment(environment) {
  const issues = [];
  for (const name of REQUIRED_ENV_NAMES) {
    if (typeof environment[name] !== 'string' || !environment[name].trim()) issues.push('ENV_MISSING:' + name);
  }
  if (environment.EPS_ENV && environment.EPS_ENV !== 'sandbox') issues.push('EPS_ENV_MUST_BE_SANDBOX');
  const transactionId = environment.EPS_TRACE_MERCHANT_TRANSACTION_ID;
  if (transactionId && !validMerchantTransactionId(transactionId)) issues.push('MERCHANT_TRANSACTION_ID_FORMAT_INVALID');
  const amount = environment.EPS_TRACE_AMOUNT;
  if (amount && (!normalizeAmount(amount) || normalizeAmount(amount) === '0.00')) issues.push('AMOUNT_FORMAT_INVALID');
  for (const name of ['EPS_TRACE_SUCCESS_URL', 'EPS_TRACE_FAIL_URL', 'EPS_TRACE_CANCEL_URL']) {
    if (environment[name] && !publicHttps(environment[name])) issues.push('CALLBACK_URL_FORMAT_INVALID:' + name);
  }
  let ecommerceOrigins;
  if (environment.EPS_TRACE_ECOMMERCE_ORIGINS) {
    try { ecommerceOrigins = JSON.parse(environment.EPS_TRACE_ECOMMERCE_ORIGINS); }
    catch { issues.push('ECOMMERCE_ORIGIN_DENYLIST_INVALID'); }
  }
  if (environment.EPS_TRACE_CALLBACK_ORIGIN && ecommerceOrigins !== undefined &&
      ['EPS_TRACE_SUCCESS_URL', 'EPS_TRACE_FAIL_URL', 'EPS_TRACE_CANCEL_URL'].every(name => environment[name])) {
    const isolation = callbackIsolationIssue({ successUrl: environment.EPS_TRACE_SUCCESS_URL,
      failUrl: environment.EPS_TRACE_FAIL_URL, cancelUrl: environment.EPS_TRACE_CANCEL_URL },
    { callbackOrigin: environment.EPS_TRACE_CALLBACK_ORIGIN, ecommerceOrigins });
    if (isolation) issues.push(isolation);
  }
  if (environment.SSLKEYLOGFILE || /--tls-keylog(?:=|\s|$)/i.test(environment.NODE_OPTIONS || '')) issues.push('EXTERNAL_TLS_KEYLOG_FORBIDDEN');
  if (environment.NODE_TLS_REJECT_UNAUTHORIZED === '0') issues.push('TLS_VALIDATION_BYPASS_FORBIDDEN');
  issues.push(...validatePreparationDetails(environment));
  return [...new Set(issues)];
}
