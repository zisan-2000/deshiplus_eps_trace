#!/usr/bin/env node
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { loadConfig, validateConfig, validateEnvironment } from './config.mjs';
import { STAGE } from './eps-contract.mjs';
import { executionSafetySummary } from './execution-safety.mjs';
import { localToolEnvironment } from './capture-readiness.mjs';

const blocked = new Set(['trace', 'run', 'auth', 'initialize', 'status']);
const knownErrors = new Set(['PAYMENT_API_EXECUTION_DISABLED_OFFLINE', 'UNKNOWN_COMMAND',
  'INVALID_ARGUMENTS', 'CONFIG_READ_OR_PARSE_FAILED', 'READINESS_SAFETY_CONFIGURATION_REQUIRED',
  'READINESS_UNSAFE_TLS_ENVIRONMENT', 'READINESS_DESTINATION_PLAN_INVALID', 'LOCAL_TOOL_EXECUTION_FAILED']);
function parseArgs(args) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--config' && typeof args[i + 1] === 'string' && !args[i + 1].startsWith('--') && !out.config) out.config = args[++i];
    else if (args[i] === '--check-env' && !out.checkEnv) out.checkEnv = true;
    else if (args[i] === '--local-only' && !out.localOnly) out.localOnly = true;
    else throw new Error('INVALID_ARGUMENTS');
  }
  return out;
}
export async function main(argv = process.argv.slice(2), environment = process.env) {
  try {
    const command = argv[0] || 'help';
    // No bypass flag or environment value can enable an unimplemented transport.
    if (blocked.has(command.toLowerCase())) throw new Error('PAYMENT_API_EXECUTION_DISABLED_OFFLINE');
    if (command === 'help') {
      console.log('DeshiPlus EPS Trace — Step 7C AUTH-only preparation\n\nCommands:\n  validate [--config FILE] [--check-env]\n  doctor [--config FILE]\n  interfaces [--config FILE]\n  readiness [--config FILE] [--local-only]\n\nUse npm run auth:mock-evidence for the fixed loopback test. The separate npm run auth:check command requires explicit interactive confirmation. Full trace, INITIALIZE and STATUS remain disabled. No .env files are loaded.');
      return 0;
    }
    if (!['validate', 'doctor', 'interfaces', 'readiness'].includes(command)) throw new Error('UNKNOWN_COMMAND');
    const args = parseArgs(argv.slice(1));
    if ((args.localOnly && command !== 'readiness') || (args.checkEnv && !['validate', 'doctor'].includes(command))) throw new Error('INVALID_ARGUMENTS');
    const cfg = loadConfig(args.config);
    const issues = validateConfig(cfg);
    if (!issues.length && args.checkEnv) issues.push(...validateEnvironment(environment));
    if (command === 'validate') {
      console.log(JSON.stringify({ valid: issues.length === 0, issues, environmentChecked: !!args.checkEnv,
        networkEnabled: false, stage: STAGE, ...executionSafetySummary() }, null, 2));
      return issues.length ? 1 : 0;
    }
    if (issues.length) {
      console.log(JSON.stringify({ valid: false, issues, networkEnabled: false }, null, 2));
      return 1;
    }
    if (command === 'interfaces' || command === 'readiness') {
      const diagnostics = await import('./network-readiness.mjs');
      if (command === 'interfaces') {
        console.log(JSON.stringify({ interfaces: diagnostics.getInterfaces(cfg.capture.tsharkPath) }, null, 2));
        return 0;
      }
      const result = await diagnostics.runReadiness(cfg, { localOnly: !!args.localOnly });
      console.log(JSON.stringify({ outcome: result.report.outcome, errors: result.report.errors,
        report: result.reportPath, pcap: result.pcapPath, tools: result.report.tools,
        hostnameCheck: result.report.hostnameCheck, capture: result.report.capture,
        safety: result.report.safety }, null, 2));
      return result.report.outcome === 'PASS' ? 0 : 1;
    }
    // Local executable/version visibility only: no capture, sockets, DNS or API request.
    const tshark = spawnSync(cfg.capture.tsharkPath, ['--version'], {
      encoding: 'utf8', windowsHide: true, shell: false, timeout: 3000,
      env: localToolEnvironment(environment), stdio: ['ignore', 'pipe', 'pipe']
    });
    const supportedNode = Number(process.versions.node.split('.')[0]) >= 20;
    console.log(JSON.stringify({ nodeVersion: process.version, supportedNode,
      configValid: true, tsharkExecutableAvailable: !tshark.error && tshark.status === 0,
      networkEnabled: false, liveRequestRunnerImplemented: true, liveRequestRunnerEnabled: false, authOnlyRunnerPrepared: true, authOnlyRequestExecuted: false, mockOnlyRequestRunnerImplemented: true,
      liveCaptureImplemented: true, liveCaptureEnabled: false, mockLoopbackCaptureImplemented: true, localCaptureProbeImplemented: true,
      tlsKeyLoggingEnabled: false, captureReadinessTested: false,
      profile: cfg.profile, plannedCapture: { interface: cfg.capture.interface, format: cfg.capture.format,
        preservePcap: cfg.capture.preservePcap, readinessRequired: cfg.capture.readinessRequired },
      ...executionSafetySummary() }, null, 2));
    return supportedNode ? 0 : 1;
  } catch (error) {
    const code = knownErrors.has(error?.message) ? error.message : 'OFFLINE_SETUP_FAILED';
    console.error(JSON.stringify({ error: code, networkEnabled: false }));
    return 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await main();
}
