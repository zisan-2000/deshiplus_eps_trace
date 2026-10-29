# EPS Step 4 standalone configuration and execution safety

`config.eps.sandbox.local.json` is the active local profile. It contains no
credential values, tokens, customer data or actual callback URLs. Credentials
remain typed environment references for `EPS_USERNAME`, `EPS_PASSWORD`,
`EPS_HASH_KEY`, `EPS_MERCHANT_ID` and `EPS_STORE_ID`. No ecommerce .env or Postman
credential value was used to populate it. It is ignored by Git.

## Reviewed evidence and its limits

Step 2 recorded 181 passing offline setup/contract tests. The V4/Postman source
discrepancies remain documented in [contract-mapping.md](contract-mapping.md);
Web type is numeric 1 and all three API methods/URLs and payload bindings are
unchanged. Those checks did not establish EPS runtime behavior.

The final Step 3 report under
`evidence/readiness/2026-10-28T07-10-24-682Z_c3fbc040/` recorded PASS: interface 5
was the active Wi-Fi adapter, Npcap/TShark capture permission worked, and a
separate synthetic loopback PCAP contained 21 packets across three TCP streams
with zero application payload. The Wi-Fi permission capture contained zero
packets. That historical report is not a permanent capture approval or proof of
EPS TCP/TLS/API availability. No real capture is required or run for Step 4.

## Local profile policies

| Area | Enforced configuration |
| --- | --- |
| Endpoints | Exact three Sandbox step URLs only; no protocol/host/path/query/fragment overrides |
| Execution | Network/payment/callback execution false; retries zero; trace always rejected by CLI |
| Capture plan | Interface 5; EPS HTTPS-only filter; PCAPNG `session.pcapng`; preservation true; capture enabled false |
| Capture failure | Readiness required, 8-second deadline, abort required; a future runner must implement these gates |
| Sensitive evidence | Raw request/response headers and bodies false; TLS key logging false; TLS verification true |
| Private configuration | Env descriptors only; example and local profiles validated independently; duplicate JSON keys rejected |
| Callback isolation | Dedicated origin and complete ecommerce-origin denylist required; shared hosts and app routes rejected |
| Attempt tracking | Private durable atomic tracking required but not implemented; no automatic restart/resume |

PCAP preservation does not redact packets. Future EPS PCAPs must remain restricted
internal artifacts. The existing readiness command uses its own fixed local
probe filters; it does not apply the EPS filter to live Wi-Fi. No EPS trace
runner, callback sender or payment capture pipeline has been added in Step 4.

## Callback isolation checks

The future private environment must supply:

- `EPS_TRACE_CALLBACK_ORIGIN`: dedicated public HTTPS origin, without a path,
  query, userinfo or fragment.
- `EPS_TRACE_ECOMMERCE_ORIGINS`: JSON array of all current ecommerce public HTTPS
  origins/aliases, with 1–32 entries. Values stay private and are not echoed.
- Existing `EPS_TRACE_SUCCESS_URL`, `EPS_TRACE_FAIL_URL`, `EPS_TRACE_CANCEL_URL`
  must use the isolated origin and, respectively, `/eps-trace/success`,
  `/eps-trace/fail`, `/eps-trace/cancel`. Step 4 accepts standard HTTPS port only.

These paths are conservative local placeholders pending an approved callback
contract, not EPS-provided receiver URLs. They contain no ecommerce order/bill
binding and must not be mapped to ecommerce callback handlers. No receiver has
been created or contacted.

Checks normalize origin hostname case, default ports and trailing dots; a denied
ecommerce hostname is blocked on every port. `/api/eps/*` and `/api/aibl-wallet/*`
routes, case variants and percent-encoded aliases are rejected. Other origins,
wrong role paths, userinfo, fragments, backslashes and queries fail. Queries are
disabled until correlation/authenticity requirements are reviewed rather than
reusing the ecommerce application's signing secret or signed URL convention.

An empty/malformed/missing denylist fails closed. A syntactically valid list is
not proof that it includes every ecommerce alias or CNAME/shared backend. Offline
checks cannot establish domain ownership or route isolation. Independent review
of the complete inventory and receiver ownership therefore remains an execution
blocker even if `validate:env` passes. The project never reads ecommerce .env to
discover or copy its secret/public-origin values automatically.

## Restart-safe transaction tracking requirements

The Step 2 in-memory registry is not restart-safe and must not be used as the
only protection for real initialization. Before a future request runner exists,
an approved private ledger must:

1. Atomically reserve a unique merchantTransactionId and CustomerOrderId in the
   Sandbox merchant-account/store scope before the first INITIALIZE request.
   Multiple processes require an exclusive lock/atomic uniqueness check; a random
   numeric ID's format alone does not prove uniqueness.
2. Durably record the original ID, customer-order reference, normalized BDT amount,
   account/store fingerprints, request-semantic fingerprint, phase and timestamp.
   The fingerprint must exclude passwords, hash keys, tokens and customer data.
3. Commit an in-flight state before sending INITIALIZE. A timeout, disconnect or
   uncertain response leaves the attempt blocked for reconciliation, never
   eligible for automatic new-ID generation or another initialization.
4. Use atomic writes/durable flush and versioned state transitions so a crash
   cannot turn an uncertain attempt into a fresh one. A restart must inspect the
   protected original binding; automatic network resume remains forbidden.
5. Protect recorded financial references with owner-only access and approved
   protected storage. Never persist credentials, JWTs, x-hash values, customer
   records or signed callback/redirect URLs in the diagnostic report or ledger.
6. Permit a future STATUS request only with the original account/ID/amount and a
   confirmed repeatability policy. Registry reservation is for new initialization,
   not for STATUS. A status-only retry does not justify a replacement bank order.

No ledger, database schema or order is created here. EPS repeatability, lost-init
recovery, token refresh and hosted redirect recovery still need documented
procedures. No unique ID or ledger status substitutes for financial verification.

## Requirements still blocking execution

`validate` and `doctor` always report `executionReady: false` in Step 4. Fixed
blocker codes cover the missing EPS request runner, unverified private Sandbox
inputs, unimplemented durable ledger, unconfirmed hosted-payment procedure,
unconfirmed isolated receiver ownership and callback delivery contract,
unverified ecommerce-origin inventory, unconfirmed STATUS polling/retry policy,
and the need for a fresh capture-readiness check.

Required external details include authorized test account/wallet and amount,
token/session lifetime, how hosted payment is completed before expecting exact
`Success`, callback method/body/query preservation/authenticity, polling limits,
retry side effects and recovery after an uncertain initialization. GET method
semantics or a read-only function name do not establish those gateway guarantees.

The JSON policy records requirements, not operator self-approval toggles. Changing
`UNCONFIRMED` fields, removing blockers, enabling requests/callbacks, disabling
TLS validation or allowing raw payloads fails validation. The CLI rejects trace,
AUTH, INITIALIZE and STATUS before loading configuration. No environment flag
or successful local check can bypass that hard stop in this version.

## Offline validation

```powershell
Set-Location E:\Ecommerce\General\deshiplus_eps_trace
npm test
npm run validate
npm run doctor
npm run validate:example
```

`npm run validate:env` is optional and checks explicit process values without
loading .env or echoing values. Missing isolation metadata is a failure; a PASS
still leaves execution blocked. Tests use synthetic credentials, identities and
origins under a socket/DNS/HTTP tripwire. Stop after Step 4.

## Step 5 continuation

The private process-environment helper is now implemented separately; see
[private-environment.md](private-environment.md). Configuration stage metadata
has advanced to Step 5 without changing the three API plans. All execution and
callback/capture blockers above remain in force. Current test results are in
`evidence/step5/offline-validation-report.json`; no real credentials, customer
data, generated identities or callbacks are recorded in that report.

## Step 7A continuation

The offline-only runner and private atomic mock journal are documented in
[offline-mock-runner.md](offline-mock-runner.md). They implement local response,
timing and PCAPNG validation without adding a live EPS transport. Accordingly the
old implementation blockers are now expressed as `LIVE_EPS_TRANSPORT_NOT_IMPLEMENTED`
and `LIVE_ATTEMPT_LEDGER_SCOPE_NOT_APPROVED`; every external procedure and fresh
readiness blocker remains. Structural validation still reports executionReady false.
