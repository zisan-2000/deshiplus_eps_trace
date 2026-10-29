# Step 7B live runner preparation (execution disabled)

Step 7B adds the real HTTPS transport and Wi-Fi Interface 5 capture coordinator,
but does not issue the internal execution capability they require. `npm run trace`,
`auth`, `initialize`, `status` and `run` fail before config or credentials are read.
No config key, command-line option or environment variable enables live execution.

## Prepared request and evidence flow

1. Validate the exact EPS Sandbox endpoint, method, request casing, HMAC-SHA512
   `x-hash`, Bearer binding, callback isolation and strict TLS settings.
2. Atomically reserve both transaction identifiers in a private, account-scoped
   journal before INITIALIZE can be claimed.
3. Start TShark on Interface 5 with
   `tcp port 443 and host sandboxpgapi.eps.com.bd`. No request may run until TShark
   reports capture start and a complete PCAPNG section/interface header exists.
4. Record sanitized DNS, TCP, TLS, first-byte and total timing. Headers, bodies,
   tokens, hashes, customer data, URLs, references and account IDs stay out.
5. After INITIALIZE, persist `AWAITING_HOSTED_PAYMENT` and stop. The toolkit does
   not open the redirect or infer a payment-completion procedure.
6. Resume requires the exact `STATUS_RESUME_CONFIRMATION`, re-authenticates without
   another INITIALIZE, then allows one STATUS. Automatic retries are zero.
7. STATUS succeeds only for HTTP 2xx, no gateway error, exact transaction ID,
   exact normalized amount and case-sensitive `Status = "Success"`.

Every future phase needs a fresh preserved `session.pcapng` and sanitized
`combined-report.json`. TLS session keys and raw payload evidence remain disabled.

## Local-only verification

`npm run live:local-evidence` uses synthetic values, an owned TLS loopback server
and the Npcap loopback interface. It never resolves or connects to EPS. Tests force
hostname lookup to `127.0.0.1` and verify DNS/TCP/TLS/HTTP timing, TLS validation,
strict response rules and retry blocking.

## Unresolved requirements

- Bank-approved hosted-payment procedure and operator ownership.
- Ownership/approval of the isolated callback receiver, plus callback delivery,
  authentication, payload and retry contract.
- Independent verification of the ecommerce-origin denylist.
- STATUS polling interval, retry ceiling, terminal states and timeout/uncertain
  INITIALIZE recovery procedure.
- Approval of account/store ledger scope and reconciliation ownership.
- Process-only validation of private Sandbox inputs and credentials.
- Fresh Interface 5 capture readiness immediately before an approved live run.

The execution decision remains **NO-GO**.
