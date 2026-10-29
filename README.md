# DeshiPlus EPS Sandbox Trace

Step 7C prepares an independent, explicitly confirmed EPS Sandbox AUTH-only
diagnostic while Step 7B's strict live transport, account-scoped attempt journal,
manual hosted-payment pause/resume, DNS/TCP/TLS/HTTP timing and Wi-Fi Interface 5
PCAPNG coordination. Live EPS execution remains hard disabled.
The explicit readiness command from Step 3 checks tools/interfaces,
optionally resolves the fixed EPS hostname and compiles its planned filter,
opens Wi-Fi with a zero-complete-frame filter, then captures payload-free
loopback TCP only. The prepared API client and capture coordinator have no issued
execution capability. All payment execution commands fail closed with exit 1.

Node.js 20 or later is required. There are no third-party npm dependencies and
no installation or database setup is needed for the offline commands.

## Files

```text
deshiplus_eps_trace/
  package.json
  .gitignore
  config.eps.sandbox.example.json
  config.eps.sandbox.local.json  # ignored, credential-free local profile
  README.md
  docs/contract-mapping.md
  src/cli.mjs
  src/config.mjs
  src/eps-contract.mjs
  src/signing.mjs
  src/contract-utils.mjs
  src/request-contract.mjs
  src/response-contract.mjs
  src/capture-readiness.mjs
  src/network-readiness.mjs
  src/execution-safety.mjs
  src/environment-preflight.mjs
  src/attempt-ledger.mjs
  src/mock-data.mjs
  src/mock-transport.mjs
  src/mock-runner.mjs
  src/mock-evidence.mjs
  src/workspace-storage.mjs
  scripts/Set-EpsSandboxEnvironment.ps1
  scripts/EpsSandboxEnvironment.psm1
  scripts/offline-validation-guard.cjs
  scripts/Run-MockEvidence.mjs
  scripts/Run-OfflineTests.mjs
  scripts/Protect-MockLedger.ps1
  scripts/Get-LocalCaptureEnvironment.ps1
  tests/no-network.cjs
  tests/setup.test.mjs
  tests/contract.test.mjs
  tests/synthetic-fixtures.mjs
  tests/readiness.test.mjs
  tests/security.test.mjs
  tests/environment.test.mjs
  tests/powershell-environment.test.mjs
  tests/environment-fixture.ps1
  tests/mock-runner.test.mjs
  tests/mock-local.test.mjs
  docs/network-readiness.md
  docs/execution-safety.md
  docs/private-environment.md
  docs/offline-mock-runner.md
```

## Offline commands

```powershell
Set-Location E:\Ecommerce\General\deshiplus_eps_trace
npm run help
npm run validate
npm run doctor
npm test
```

| Command | Behavior |
| --- | --- |
| `npm run help` | Lists the offline command boundary |
| `npm run validate` | Checks the local profile, exact EPS mappings and execution blockers |
| `npm run validate:example` | Checks the distributable example profile |
| `npm run validate:env` | Optional private process-environment presence/format check; missing names only are reported |
| `npm run doctor` | Checks Node support and local TShark executable visibility; no capture or network readiness test |
| `npm run interfaces` | Lists local TShark interfaces without capturing |
| `npm run readiness` | Explicit fixed-host DNS/filter check plus constrained Wi-Fi permission and synthetic loopback capture probes |
| `npm run readiness:local` | Same local probes with EPS DNS/filter checks skipped; no external networking |
| `npm test` | All offline setup/contract/readiness/security/environment suites, including synthetic PowerShell helper tests |
| `npm run test:contract` | Response, request, correlation, uniqueness and HMAC contract tests only |
| `npm run test:readiness` | Offline readiness/parser/fake-process tests; no real capture or sockets |
| `npm run test:security` | Offline local-config, callback-isolation and execution-safety tests |
| `npm run test:environment` | Synthetic environment and PowerShell 5.1/7 helper tests; no real inputs |
| `npm run test:mock` | Socket-blocked mock flow, ledger, recovery and sanitization tests |
| `npm run test:mock-local` | Explicit TLS loopback, prepared transport and PCAPNG tests |
| `npm run mock:evidence` | Generates sanitized synthetic combined report and loopback session.pcapng |
| `npm run live:local-evidence` | Generates sanitized Step 7B local-only evidence and session.pcapng |
| `npm run auth:mock-evidence` | Generates sanitized AUTH-only loopback evidence without contacting EPS |
| `npm run auth:check` | Explicit one-request EPS Sandbox AUTH diagnostic using protected `.env.local` values or hidden fallback prompts, with Interface 5 capture |
| `npm run trace` | Intentionally exits 1 with `PAYMENT_API_EXECUTION_DISABLED_OFFLINE` |

Direct `auth`, `initialize`, `status`, `run` and `trace` CLI commands are also
disabled. No flag or environment variable enables them. Changing any disabled
execution flag in JSON causes validation to fail. `doctor` does not prove Npcap
or adapter readiness; the explicit constrained `readiness` command checks those.

## Configuration and private inputs

Commands and the CLI default to `config.eps.sandbox.local.json`. This file was
created for Step 4, is ignored by Git and contains environment references only.
The example remains a separately validated template. Structural validation can
PASS while `executionReady` remains false; both validate and doctor print the
remaining fixed blocker codes. No JSON or environment flag enables trace.

The JSON file is a request plan. An object such as
`{"env":"EPS_TRACE_AMOUNT","type":"number"}` is a typed binding descriptor,
not the EPS wire payload. A future reviewed renderer must produce a JSON number
for `totalAmount`; merchant transaction IDs must remain strings. Web payment
`transactionTypeId` is the numeric literal `1`.

`signing` describes the future `x-hash` header: HMAC-SHA512, UTF-8 key/input,
Base64 output. AUTH hashes the username. INITIALIZE and STATUS hash the original
merchant transaction ID. INITIALIZE/STATUS use the token extracted from AUTH as
`Authorization: Bearer <token>`. No static JWT is accepted in the template.
`src/signing.mjs` contains only a pure offline HMAC function; it does not read
credentials or transmit anything.

Ordinary CLI, validation, doctor, readiness and offline-test commands do not load
`.env` files. The independent `npm run auth:check` wrapper alone may load the
project-root `.env.local`, after capture readiness and before its single AUTH
child starts. It accepts only the five credential names below, fails on malformed
or duplicate entries, and fails closed if a nonempty process value conflicts with
the corresponding file value. Missing AUTH values use hidden prompts. Do not copy
credentials or sample JWTs from Postman or the ecommerce project.

`.env.local` uses literal `KEY=value` lines. Everything after the first `=` is
preserved, including spaces, `#`, `$`, quotes and additional `=` characters. Do
not add wrapping quotes unless those quote characters are part of the secret.
The file is Git-ignored and its Windows ACL is restricted to the current user,
SYSTEM and local administrators. The accepted credential names are:

- `EPS_ENV` must be `sandbox`.
- Credentials: `EPS_USERNAME`, `EPS_PASSWORD`, `EPS_HASH_KEY`,
  `EPS_MERCHANT_ID`, `EPS_STORE_ID`.
- Correlation: `EPS_TRACE_CUSTOMER_ORDER_ID`,
  `EPS_TRACE_MERCHANT_TRANSACTION_ID` (Step 5 generates 23 decimal digits kept as a string; underlying API policy accepts 10–30),
  `EPS_TRACE_AMOUNT` (positive BDT amount, at most eight whole digits/two decimals).
- Callbacks: `EPS_TRACE_SUCCESS_URL`, `EPS_TRACE_FAIL_URL`, `EPS_TRACE_CANCEL_URL`.
- Isolation metadata: `EPS_TRACE_CALLBACK_ORIGIN` (dedicated public HTTPS origin
  only) and `EPS_TRACE_ECOMMERCE_ORIGINS` (JSON array of all ecommerce HTTPS
  origins/aliases, supplied privately without copying the app .env).
- Synthetic customer/product inputs: `EPS_TRACE_CUSTOMER_NAME`,
  `EPS_TRACE_CUSTOMER_EMAIL`, `EPS_TRACE_CUSTOMER_ADDRESS`, `EPS_TRACE_CUSTOMER_CITY`,
  `EPS_TRACE_CUSTOMER_STATE`, `EPS_TRACE_CUSTOMER_POSTCODE`,
  `EPS_TRACE_CUSTOMER_COUNTRY`, `EPS_TRACE_CUSTOMER_PHONE`, `EPS_TRACE_PRODUCT_NAME`.

Do not enter secrets as command arguments or paste environment values into
reports. `validate:env` checks presence and basic syntax only; it cannot establish
credential validity, callback ownership, reachability or payment readiness.

Use isolated Sandbox callback destinations and synthetic test inputs in any
future standalone test. Ecommerce callback handlers reconcile stored payment
attempts and can settle orders; a toolkit-generated reference is not an ecommerce
Payment/order. The helper generates unused local candidate IDs only. It generates
no signed callbacks, opens no hosted URL and triggers no callback.

Step 4 requires the three paths `/eps-trace/success`, `/eps-trace/fail` and
`/eps-trace/cancel` on the isolated origin. Shared ecommerce hostnames are denied
across case/default-port/trailing-dot variants and other ports. App callback
routes, including encoded `/api/eps/*` aliases, are rejected even on another host.
Query parameters are forbidden until the actual standalone callback contract is
reviewed. These are conservative toolkit policies, not bank-approved receiver
paths. Missing isolation metadata fails private-input validation. Offline checks
cannot establish receiver ownership, an authoritative denylist or DNS/backend
separation; execution remains blocked for those reviews.

## Offline contract checks

`validateEpsRequest` checks concrete synthetic JSON requests, exact Sandbox
endpoints, headers, HMAC and original transaction/amount bindings. It receives
private context explicitly and returns only an acceptance flag and fixed code.
It does not render request plans, read secrets, reserve a real transaction or
transmit requests.

`validateEpsResponse` checks HTTP status separately from gateway JSON codes,
bounded UTF-8 JSON objects, duplicate keys, casing and each operation's business
rules. Only STATUS with the exact original ID, matching normalized amount and
exact `Success` returns `paymentVerified: true`. Unknown statuses return PENDING;
provider failure/cancellation labels are not guessed. Results contain no raw
token, URL, ID, amount, customer field or arbitrary provider message.

The in-memory identity registry rejects reuse of either merchant transaction ID
or CustomerOrderId while the registry exists. It cannot prove merchant-wide
uniqueness, survive a restart or replace a future private attempt ledger. The Step 5
helper also checks generated IDs in memory only. See [contract-mapping.md](docs/contract-mapping.md)
for the exact rules, stricter toolkit policies and remaining unconfirmed behavior.
The local profile now requires a private durable atomic attempt ledger before
initialization. Only its requirements are defined; no ledger exists or is written.
See [execution-safety.md](docs/execution-safety.md) for crash/restart requirements.

## Security and future diagnostic work

EPS network/payment requests, retries and payment-session capture are disabled. TLS verification is
required, TLS key logging is disabled and no key-log collector exists. Raw
request/response bodies and headers are disabled. Planned masks cover credentials,
transaction references, callback/redirect URLs and customer data. There is no
evidence writer yet, so these flags are plans rather than a redaction guarantee.

The local profile plans PCAPNG output as `session.pcapng` on interface `5`, with
preservation enabled, an 8-second readiness deadline and abort-on-capture-failure.
`capture.enabled` remains false. These are future integrated-trace requirements;
they do not create a Bank capture runner or authorize live Wi-Fi collection.

The readiness command is independent of the disabled payment runner. It uses
fixed safe capture plans and does not apply the future EPS filter to live Wi-Fi.
It writes a sanitized report, an empty Wi-Fi permission PCAPNG and synthetic
`session.pcapng` under ignored `evidence/readiness/`. No sensitive raw payload is
recorded; external tools do not inherit EPS credentials or TLS key-log options.
See [network-readiness.md](docs/network-readiness.md) for the checks and limits.

Future phases can add bounded HTTP execution integrated with these validators,
DNS/TCP/TLS timings and per-request packet correlation. Interface `5` must be
reidentified before future sessions. PCAPs remain sensitive, even with TLS keys
disabled. Hosted payment completion,
isolated callback procedure and safe status-query behavior need separate review
before any Sandbox traffic. See [contract-mapping.md](docs/contract-mapping.md)
for source conflicts and exact response expectations.

## Private environment preparation (Step 5)

```powershell
Set-Location E:\Ecommerce\General\deshiplus_eps_trace
& .\scripts\Set-EpsSandboxEnvironment.ps1
```

Run in the current PowerShell process. All inputs are hidden; no secrets or IDs
are printed/saved. Without an available approved isolated callback receiver,
answer `BLOCKED` at the first prompt; credentials will not be requested. Existing
identities are never overwritten. Failed validation restores prior process
values. Successful preparation still leaves execution blocked. See
[private-environment.md](docs/private-environment.md) for inputs, validation,
limitations and remaining blockers.

The Step 5 helper remains the only process-scoped private-input preparation path.
Its offline PASS is not Sandbox execution approval.

## Offline mock trace (Step 7A)

```powershell
Set-Location E:\Ecommerce\General\deshiplus_eps_trace
npm test
npm run mock:evidence
```

The evidence command is fixed to synthetic success over an owned numeric-loopback
TLS listener. It does not read process credentials, resolve EPS DNS, contact EPS,
open a hosted page, trigger callbacks or access a database. The mock journal is
restart-safe and atomic for its explicit mock scope; live ledger scope remains an
approval blocker. See [offline-mock-runner.md](docs/offline-mock-runner.md).

`npm run trace` remains disabled. Stop after Step 7A; `MOCK_SUCCESS` is not EPS
Sandbox success or authorization to begin live execution.
