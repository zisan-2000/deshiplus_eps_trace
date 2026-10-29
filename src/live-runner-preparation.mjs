import { createHmac } from 'node:crypto';
import { AttemptLedger } from './attempt-ledger.mjs';
import { buildEpsRequest } from './request-builder.mjs';
import { validateEpsResponse } from './response-contract.mjs';
import { callbackIsolationIssue } from './execution-safety.mjs';
import { requestLiveExecutionCapability, liveExecutionGateSummary } from './live-execution-gate.mjs';
import { createLiveEpsTransport } from './live-http-transport.mjs';

export const STATUS_RESUME_CONFIRMATION = 'EPS_HOSTED_PAYMENT_PROCEDURE_COMPLETED_AND_STATUS_CHECK_APPROVED';

export function accountScopeFingerprint(context) {
  if (![context?.hashKey,context?.merchantId,context?.storeId].every(v=>typeof v==='string'&&v.trim())) throw Error('LIVE_SCOPE_INPUT_INVALID');
  return createHmac('sha512',context.hashKey).update('EPS_SANDBOX\0'+context.merchantId+'\0'+context.storeId).digest('hex').slice(0,64);
}

export function validateLiveContext(context) {
  const issue=callbackIsolationIssue({successUrl:context?.successUrl,failUrl:context?.failUrl,cancelUrl:context?.cancelUrl},context);
  if(issue)throw Error(issue);
  for(const step of ['AUTH','INITIALIZE'])buildEpsRequest(step,{...context,token:step==='INITIALIZE'?(context.token??'SYNTHETIC_VALIDATION_TOKEN'):context.token});
  return true;
}

export function prepareLiveAttempt(context, directory='.private/live-ledger') {
  validateLiveContext(context);
  const ledger=new AttemptLedger(directory,{scopeFingerprint:accountScopeFingerprint(context)});
  return {ledger,attempt:ledger.reserve(context)};
}

export function authorizeStatusResume(ledger, attemptId, confirmation) {
  if(confirmation!==STATUS_RESUME_CONFIRMATION)throw Error('LIVE_STATUS_RESUME_NOT_CONFIRMED');
  return ledger.transition(attemptId,'OPERATOR_AUTHORIZE_STATUS');
}

export function validateStrictStep(step, raw, context) {
  return validateEpsResponse(step,raw,context);
}

export function createDisabledLiveRunner(network) {
  const capability=requestLiveExecutionCapability();
  return createLiveEpsTransport(capability,network);
}

export function liveRunnerPreparationSummary() {
  return Object.freeze({transportImplemented:true,executionGate:liveExecutionGateSummary(),automaticRetries:0,
    hostedPayment:'MANUAL_UNCONFIRMED_PROVIDER_PROCEDURE',statusResumeConfirmationRequired:true,
    callbackReceiver:'ISOLATED_OWNERSHIP_UNCONFIRMED',ledger:'PRIVATE_ATOMIC_ACCOUNT_SCOPED'});
}
