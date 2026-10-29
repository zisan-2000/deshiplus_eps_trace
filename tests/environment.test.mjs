import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { validateEnvironment, validateConfig } from '../src/config.mjs';
import { createLocalConfig, REQUIRED_ENV_NAMES } from '../src/eps-contract.mjs';
import { SYNTHETIC_CUSTOMER_ENV, hmacSelfTest } from '../src/environment-preflight.mjs';
import { executionSafetySummary } from '../src/execution-safety.mjs';
import { epsXHash } from '../src/signing.mjs';
import { syntheticEnvironment } from './synthetic-fixtures.mjs';

test('complete synthetic environment is valid while execution remains blocked', () => {
  assert.deepEqual(validateEnvironment(syntheticEnvironment()), []);
  assert.equal(executionSafetySummary().executionReady, false);
  assert.equal(hmacSelfTest(), true);
});
for (const name of REQUIRED_ENV_NAMES) test('missing input reports only its name: ' + name, () => {
  const env = syntheticEnvironment(); delete env[name];
  assert.ok(validateEnvironment(env).includes('ENV_MISSING:' + name));
});
for (const name of ['EPS_USERNAME','EPS_PASSWORD','EPS_HASH_KEY','EPS_MERCHANT_ID','EPS_STORE_ID']) {
  for (const [i,value] of ['SYNTHETIC\nPRIVATE','SYNTHETIC\rPRIVATE','SYNTHETIC\x00PRIVATE','\ud800'].entries()) {
    test('credential encoding rejected without value output: ' + name + '/' + i, () => {
      const result = validateEnvironment({...syntheticEnvironment(), [name]:value});
      assert.ok(result.includes('ENV_INVALID:' + name));
      assert.ok(!JSON.stringify(result).includes(value));
    });
  }
}
for (const name of Object.keys(SYNTHETIC_CUSTOMER_ENV)) test('real customer replacement prohibited: ' + name, () => {
  assert.ok(validateEnvironment({...syntheticEnvironment(),[name]:'SYNTHETIC_ALTERED'}).includes('ENV_INVALID:' + name));
});
for (const amount of ['0','0.00','-1','NaN','1e2','1.234','100','0100.25','100.2']) test('invalid or noncanonical amount rejected: ' + amount, () => {
  assert.ok(validateEnvironment({...syntheticEnvironment(),EPS_TRACE_AMOUNT:amount}).length > 0);
});
for (const [i,changes] of [
  {EPS_TRACE_MERCHANT_TRANSACTION_ID:'1234567890'}, {EPS_TRACE_MERCHANT_TRANSACTION_ID:'synthetic'},
  {EPS_TRACE_CUSTOMER_ORDER_ID:'synthetic-order'}, {EPS_TRACE_CUSTOMER_ORDER_ID:'DPEPS-11111111111111111111111-0123456789abcdef'}
].entries()) test('preparation identity must be numeric and correlated: ' + i, () => {
  assert.ok(validateEnvironment({...syntheticEnvironment(),...changes}).length > 0);
});
for (const name of ['EPS_TOKEN','EPS_AUTH_TOKEN','EPS_ACCESS_TOKEN','EPS_BEARER_JWT','EPS_JWT']) test('static token forbidden: ' + name, () => {
  assert.ok(validateEnvironment({...syntheticEnvironment(),[name]:'SYNTHETIC_TOKEN'}).includes('STATIC_EPS_TOKEN_FORBIDDEN'));
});
test('UTF8 key is used literally and sensitive HMAC output never enters validation report', () => {
  const env = syntheticEnvironment(); env.EPS_HASH_KEY = 'synthetic+/key==';
  const signature = epsXHash(env.EPS_USERNAME,env.EPS_HASH_KEY);
  assert.equal(signature,createHmac('sha512',Buffer.from(env.EPS_HASH_KEY,'utf8')).update(env.EPS_USERNAME,'utf8').digest('base64'));
  const report = JSON.stringify(validateEnvironment(env));
  for (const value of [signature,env.EPS_HASH_KEY,env.EPS_PASSWORD,env.EPS_TRACE_SUCCESS_URL]) assert.ok(!report.includes(value));
});
test('TLS key logging and bypass are rejected and Web type cannot change', () => {
  assert.ok(validateEnvironment({...syntheticEnvironment(),NODE_OPTIONS:'--tls-keylog=synthetic'}).includes('EXTERNAL_TLS_KEYLOG_FORBIDDEN'));
  assert.ok(validateEnvironment({...syntheticEnvironment(),NODE_TLS_REJECT_UNAUTHORIZED:'0'}).includes('TLS_VALIDATION_BYPASS_FORBIDDEN'));
  const cfg=createLocalConfig(); cfg.steps[1].body.transactionTypeId=10; assert.ok(validateConfig(cfg).includes('WEB_TRANSACTION_TYPE_MUST_BE_1'));
});
