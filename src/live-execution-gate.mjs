// Step 7B prepares production-capable components without issuing an execution
// capability. No environment variable, config value or CLI argument can bypass it.
const capabilities = new WeakSet();

export function requestLiveExecutionCapability() {
  throw new Error('LIVE_EPS_EXECUTION_NOT_APPROVED');
}

export function assertLiveExecutionCapability(value) {
  if (!value || !capabilities.has(value)) throw new Error('LIVE_EPS_EXECUTION_NOT_APPROVED');
  return true;
}

export function liveExecutionGateSummary() {
  return Object.freeze({ implemented: true, enabled: false, bypasses: [], code: 'LIVE_EPS_EXECUTION_NOT_APPROVED' });
}
