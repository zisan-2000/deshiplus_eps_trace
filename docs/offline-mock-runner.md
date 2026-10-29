# Step 7A: offline mock trace runner

Step 7A implements a strictly synthetic runner for the existing AUTH →
INITIALIZE → hosted-payment pause → STATUS contract. It can use an in-memory
mock or a toolkit-owned TLS listener bound to numeric `127.0.0.1`. It cannot
select a hostname, URL, proxy, credential source or EPS destination. The only
public evidence command has fixed success inputs:

```powershell
Set-Location E:\Ecommerce\General\deshiplus_eps_trace
npm run mock:evidence
```

This command starts TShark on the Npcap loopback interface with a capture filter
for the newly allocated local port. Capture readiness must be observed before
the first mock request. It produces `combined-report.json` and `session.pcapng`
under an ignored `evidence/mock/<session>` directory. It performs no DNS lookup,
opens no hosted URL and sends no callback. Timings measure the owned loopback
TCP/TLS/HTTP exchange; they say nothing about EPS latency or availability.

`npm run trace`, direct `auth`, `initialize`, `status` and `run` remain hard
blocked before configuration or environment values are loaded. No JSON or env
setting enables the live transport. The config keeps payment/network/callback
execution and capture disabled, TLS verification enabled, automatic retries at
zero, TLS key logging disabled and all raw request/response evidence disabled.
The mock runner also aborts before opening its listener if `SSLKEYLOGFILE`, a
Node TLS-keylog option or TLS certificate bypass is present. The test orchestrator
removes those settings and all ambient `EPS_*` values from its child processes.

## Durable mock attempt ledger

The append-only journal lives under ignored `.private/mock-ledger`. On Windows,
the directory inheritance is removed and access is restricted to the current
user SID and Local System. Every operation obtains an exclusive create-only lock.
Journal records are individually fsynced and chained by sequence, previous digest
and current digest. A complete durable `INITIALIZE_IN_FLIGHT` claim is written
before the mock request. Duplicate merchantTransactionId or CustomerOrderId,
stale lock, missing journal, invalid transition, torn record, changed historical
field or digest mismatch fails closed and requires reconciliation.

The ledger stores only a random diagnostic-attempt ID, both synthetic correlation
IDs, canonical amount, a fixed mock-scope fingerprint and phase. It never stores
credentials, token, hash key, callback URL, redirect URL, bank reference or
customer data. An INITIALIZE timeout becomes `INITIALIZE_UNCERTAIN`; the runner
cannot resume or create the same identity again. STATUS transport uncertainty is
also terminal locally because provider retry safety is unconfirmed.

The ledger is intentionally marked mock-scope only. Its implementation passing
local durability/concurrency tests does not approve its storage location, scope,
retention or reconciliation workflow for a real merchant attempt.

## Hosted-payment gate and validation

After successful INITIALIZE the attempt is `AWAITING_HOSTED_PAYMENT` and the
runner stops unless the caller explicitly requests synthetic hosted completion.
The test runner then records `HOSTED_COMPLETION_SIMULATED`; it does not visit the
RedirectURL or trigger a callback. A paused mock attempt can be resumed only with
that explicit simulation flag, and resume performs STATUS without repeating AUTH
or INITIALIZE. The synthetic token used during resume is never persisted.

STATUS is accepted only when HTTP is 2xx, JSON is bounded and well formed, error
fields indicate no error, MerchantTransactionId exactly matches the original,
amount normalizes exactly to the original amount, and case-sensitive `Status` is
exactly `Success`. HTTP 101 is kept as an HTTP failure; JSON `ErrorCode: 101` is a
separate business failure. Pending/unknown status, mismatch, malformed/oversize
response, redirect and timeout never become payment success.

## Evidence safety

The report is constructed from a small allowlist instead of redacting arbitrary
objects. It includes fixed outcome codes, HTTP status, local timing categories,
mock lifecycle events, packet counts and safety flags. It excludes wire URLs,
headers, bodies, IDs used for payment correlation, amount, token, credentials,
hashes, callback/redirect URLs, provider messages and customer/product fields.
The random diagnostic attempt ID is only a local journal correlation key.

TLS uses a committed synthetic loopback-only certificate and verified CA binding.
No session key file is generated. The PCAP validator requires only 127.0.0.1,
the owned dynamic port, valid ordered timestamps, one or more TCP streams and TLS
records. It scans the PCAP bytes for synthetic secret/customer sentinels and fails
if plaintext is found. It never captures Wi-Fi or unrelated traffic.

## Offline test coverage

`npm test` runs the socket-blocked contract/config/environment/ledger suite first,
then the explicit local TLS tests. Tests cover cross-process atomic reservation,
duplicate prevention, stale locks, torn journals, uncertain INITIALIZE, pause and
resume, no automatic retry, strict response correlation, report allowlisting,
TLS verification, timeout/size bounds and readable scoped PCAPNG evidence.

The generated Step 7A sample is synthetic mock evidence, never bank evidence.
Live execution remains NO-GO until private Sandbox inputs are authorized and
verified; a live transport and approved live ledger scope/reconciliation process
exist; callback ownership/delivery/correlation and the ecommerce denylist are
confirmed; hosted-payment and test-wallet procedure are approved; STATUS polling,
retry/rate limits, token refresh and uncertain-response recovery are documented;
and fresh Wi-Fi Interface 5 capture readiness passes immediately before execution.

Stop after Step 7A. Do not reinterpret local `MOCK_SUCCESS` as EPS success.
