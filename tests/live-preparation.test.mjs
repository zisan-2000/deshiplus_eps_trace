import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { requestLiveExecutionCapability, assertLiveExecutionCapability, liveExecutionGateSummary } from '../src/live-execution-gate.mjs';
import { createLiveEpsTransport } from '../src/live-http-transport.mjs';
import { LIVE_CAPTURE_PLAN, validateLiveCaptureConfig, withLiveCapture } from '../src/live-capture.mjs';
import { createLocalConfig } from '../src/eps-contract.mjs';
import { createMockContext } from '../src/mock-data.mjs';
import { AttemptLedger } from '../src/attempt-ledger.mjs';
import { accountScopeFingerprint, authorizeStatusResume, STATUS_RESUME_CONFIRMATION } from '../src/live-runner-preparation.mjs';
import { PROJECT_ROOT } from '../src/workspace-storage.mjs';

test('live execution capability cannot be obtained or forged',()=>{
  assert.throws(()=>requestLiveExecutionCapability(),/LIVE_EPS_EXECUTION_NOT_APPROVED/);
  assert.throws(()=>assertLiveExecutionCapability({}),/LIVE_EPS_EXECUTION_NOT_APPROVED/);
  assert.throws(()=>createLiveEpsTransport({},{}),/LIVE_EPS_EXECUTION_NOT_APPROVED/);
  assert.deepEqual(liveExecutionGateSummary(),{implemented:true,enabled:false,bypasses:[],code:'LIVE_EPS_EXECUTION_NOT_APPROVED'});
});

test('Wi-Fi 5 capture plan is exact, payload-safe and gated before process launch',async()=>{
  const cfg=createLocalConfig();
  assert.equal(validateLiveCaptureConfig(cfg),true);
  assert.deepEqual(LIVE_CAPTURE_PLAN,{interface:'5',filter:'tcp port 443 and host sandboxpgapi.eps.com.bd',format:'pcapng',fileName:'session.pcapng',preserve:true,tlsKeyLogging:false,rawPayloadReport:false});
  let spawned=false;
  await assert.rejects(()=>withLiveCapture({},cfg,'evidence/never',async()=>{}, {spawnProcess(){spawned=true;}}),/LIVE_EPS_EXECUTION_NOT_APPROVED/);
  assert.equal(spawned,false);
});

test('account-scoped ledger requires explicit hosted-payment STATUS authorization and never re-initializes',()=>{
  const context=createMockContext();
  const scope=accountScopeFingerprint(context);
  assert.match(scope,/^[a-f0-9]{64}$/);
  const relative=path.join('tmp','live-ledger-'+randomUUID());
  const ledger=new AttemptLedger(relative,{scopeFingerprint:scope});
  const attempt=ledger.reserve(context);
  ledger.transition(attempt.id,'AUTH_OK'); ledger.transition(attempt.id,'CLAIM_INITIALIZE'); ledger.transition(attempt.id,'INITIALIZE_OK');
  assert.throws(()=>authorizeStatusResume(ledger,attempt.id,'yes'),/LIVE_STATUS_RESUME_NOT_CONFIRMED/);
  assert.equal(authorizeStatusResume(ledger,attempt.id,STATUS_RESUME_CONFIRMATION).phase,'STATUS_CHECK_AUTHORIZED');
  ledger.transition(attempt.id,'CLAIM_REAUTH');ledger.transition(attempt.id,'REAUTH_OK');
  assert.equal(ledger.transition(attempt.id,'CLAIM_STATUS').phase,'STATUS_IN_FLIGHT');
  assert.throws(()=>ledger.transition(attempt.id,'CLAIM_INITIALIZE'),/LEDGER_PHASE_REJECTED/);
  const journal=fs.readFileSync(path.join(PROJECT_ROOT,relative,'events.ndjson'),'utf8');
  for(const secret of [context.username,context.password,context.hashKey,context.token,context.customerEmail])assert.ok(!journal.includes(secret));
});
