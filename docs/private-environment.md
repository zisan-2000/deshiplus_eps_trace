# EPS Step 5: private process environment

The helper prepares inputs only. It cannot authenticate, initialize a payment,
query STATUS, open a hosted page, deliver callbacks or start capture. No receiver
or durable attempt ledger is created. The existing three API plans remain
unchanged; Web `transactionTypeId` remains the numeric constant `1`.

## Current decision

Offline implementation and synthetic tests can PASS independently of execution
approval. The local profile still records callback ownership/delivery as
`UNCONFIRMED`; no approved dedicated callback origin was available in this
session's process environment. Real credentials were not collected. This is an
execution blocker, not a reason to use the ecommerce callback or invent a receiver.

## Exact command and prompts

Run in the existing private PowerShell session that should retain the variables:

```powershell
Set-Location E:\Ecommerce\General\deshiplus_eps_trace
& .\scripts\Set-EpsSandboxEnvironment.ps1
```

Do not launch through npm or a new `powershell -File` child if variables should
remain in your current shell. The project changes no execution policy. The helper
takes no plaintext credential arguments. `$LASTEXITCODE` is zero on offline
preparation PASS and one on blocked/invalid preparation.

1. Guarded Node `validate` checks structural configuration first. Existing
   transaction/order IDs, static EPS tokens, TLS key logging or TLS bypass block
   preparation before prompts. Existing identities are never overwritten.
2. The first hidden prompt asks whether a dedicated approved Sandbox receiver is
   available. Enter `BLOCKED` if unavailable or unapproved; this stops before
   requesting credentials. `APPROVED` is an operator assertion, not verified
   ownership or bank approval, and never changes execution blockers.
3. Only with an approved receiver, enter its origin, the complete ecommerce
   HTTPS-origin denylist as a JSON array, and three exact approved callback URLs.
   No URL is generated or contacted; all inputs are hidden.
4. Privately enter the issued Sandbox username, password, UTF-8 hash key,
   Merchant ID and Store ID. Do not use Postman samples, embedded JWTs or
   ecommerce `.env`. Missing credentials are reported by variable name only.
5. Enter an approved positive BDT amount: up to eight whole digits/two decimals.
   It is normalized to two decimals without rounding. Zero, signs, exponent
   notation and excess precision fail. Local candidate IDs and a fixed synthetic
   customer/product profile are generated; no real customer data is prompted for.
6. All 23 required variables are staged with `EnvironmentVariableTarget.Process`
   only. Fixed guarded `validate --check-env` runs; only after PASS are they
   retained. Failure restores previous values. Output contains fixed issue codes
   and variable names, never entered values or raw validator errors.

The five credentials are `EPS_USERNAME`, `EPS_PASSWORD`, `EPS_HASH_KEY`,
`EPS_MERCHANT_ID`, `EPS_STORE_ID`. The other 18 names are `EPS_ENV`, 15 existing
transaction/customer/callback inputs, `EPS_TRACE_CALLBACK_ORIGIN` and
`EPS_TRACE_ECOMMERCE_ORIGINS` (see README). No static token is required.

## Synthetic inputs and correlation

merchantTransactionId is a string of 13 UTC millisecond digits and ten
cryptographically random decimal digits. CustomerOrderId is
`DPEPS-<same merchantTransactionId>-<16 lowercase random hex digits>`. Both are
checked for reuse within the imported module lifetime. An already-populated
process identity blocks preparation before replacement.

These are unused local candidates, not ecommerce Payment IDs, bank orders or
merchant-wide reservations. Generation is probabilistic and the registry is not
restart-safe. Before future INITIALIZE, a reviewed private durable ledger must
atomically reserve both IDs in account/store scope and handle concurrency,
uncertain responses and restarts. Never regenerate IDs as a retry strategy.

Customer name/address/city/state/product are fixed synthetic labels; email uses
reserved `example.com`, phone is eleven zeroes, postcode four zeroes, country
Bangladesh. Offline validation requires the exact profile. EPS acceptance of
placeholders, test wallet/contact requirements and permitted amount remain
unconfirmed. Format PASS is not an approved hosted-payment procedure.

Callbacks must follow the existing conservative policy: one distinct public
HTTPS origin, standard HTTPS port and `/eps-trace/success`, `/eps-trace/fail`,
`/eps-trace/cancel` respectively. No query, fragment or userinfo. Ecommerce hosts,
aliases and payment callback routes are blocked. These paths are toolkit policy,
not proof of EPS approval. Ownership, complete denylist, DNS/backend separation
and delivery contract require independent review. No reachability/DNS test runs.

## Signing and secret handling

V4 and the supplied integration specify HMAC-SHA512, UTF-8 input/key and Base64
output. AUTH signs the exact username; INITIALIZE/STATUS sign the original
merchantTransactionId string. Do not Base64-decode the hash key or trim/normalize
credentials. A public RFC 4231 self-test and local signing shape checks run
without returning/logging hashes. A future reviewed runner would privately obtain
a fresh AUTH token; no static JWT is loaded.

Prompts use `Read-Host -AsSecureString`; conversion BSTR is zeroed and SecureString
disposed. PowerShell/Node necessarily hold plaintext strings temporarily for
validation and process environment assignment. Managed-string memory wiping is
not guaranteed. Process environment is not a vault and privileged local processes
can inspect it. Close the private shell when finished; avoid transcripts/debugger
dumps and launching unrelated children that could inherit credentials.

Private prompt values have a local 4,096-character cap. NUL/unpaired Unicode are
rejected before Windows environment assignment; credentials also reject CR/LF.
No credential is silently truncated, trimmed or re-encoded for validation.

The validation child receives only OS/tool essentials and the explicit 23
variables, without inherited NODE_OPTIONS, TLS key logging or unrelated secrets.
A preloaded guard denies HTTP/HTTPS, fetch, DNS, sockets/listeners and child
launches before execution. The command is fixed to `validate`, has a 15-second
deadline, and never invokes npm, TShark, trace or readiness. The public helper
accepts no command injection parameter; its module's SecureString provider hook
exists for synthetic automated tests only.

No credential, key, hash, token, URL, customer input or generated identity is
written to files, command arguments or reports by the helper. Configs contain env
descriptors only. Offline PASS checks format/presence and local signing mechanics;
it does not prove EPS accepts credentials.

## Offline checks and remaining blockers

```powershell
npm test
npm run test:environment
npm run validate
npm run validate:example
npm run doctor
```

Tests use disposable Windows PowerShell 5.1 and PowerShell 7 children with
synthetic SecureString providers. They cover success, rollback, missing/invalid
inputs, approval refusal before credentials, identity correlation/reuse protection,
static-token/TLS rejection and sanitized errors. Guard probes fail before any
socket, DNS lookup or child launch. No EPS/example-host request is sent.

No real capture runs for Step 5. Capture, raw sensitive evidence, TLS key logging,
callbacks and EPS execution remain disabled. Interface 5 and the future PCAPNG
plan are preserved; historical readiness does not replace fresh checks later.

Execution stays NO-GO until authorized private credential/test scope verification;
isolated callback ownership, delivery/correlation and complete ecommerce-origin
inventory review; hosted-payment/test wallet/contact/amount confirmation; durable
atomic attempt tracking and a reviewed bounded request/evidence runner; documented
STATUS repeatability/polling/rate limits, token refresh and uncertain-init recovery;
and fresh capture readiness. Exact STATUS `Success`, original ID and amount
matching remain mandatory. GET alone proves no side-effect guarantee.

Stop after Step 5. No EPS request or payment is executed by this setup.
