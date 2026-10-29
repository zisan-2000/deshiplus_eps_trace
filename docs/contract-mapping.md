# EPS Sandbox Step 2 contract verification

Reviewed sources are the supplied seven-page EPS Sandbox Merchant API Integration
Guide V4, supplied three-request Postman collection, and read-only ecommerce
`lib/eps.ts`, `lib/eps-settings.ts`, `lib/eps-callback.ts`, EPS init/status routes.
The AIBL diagnostic CLI/capture/report architecture was inspected as a reference.
No ecommerce modules are imported, no database is connected, and no ecommerce
`.env` or separate credential note is read. The supplied PDF/collection are not copied into this
project because their examples contain sensitive values.

Source-file SHA-256 identifiers (not credentials):

- V4 PDF: `8027d7d0c7dc6f90d583ba54b9ae86739d39c077c93da3ecb420cd0f60dfaffe`
- Postman collection: `89df6be6e9caa709d0d44928515faf6e3944a1d585d8eba2915a9a6a53721942`

## Exact request plans

All request/response documents are JSON. The base URL is fixed to
`https://sandboxpgapi.eps.com.bd/v1`. No live URL is inferred.

| Step | Method and path | HMAC-SHA512 input | Bearer token | Response paths |
| --- | --- | --- | --- | --- |
| AUTH | POST `/Auth/GetToken` | Exact username | None | Root `token`; lower-case `errorCode`, `errorMessage` |
| INITIALIZE | POST `/EPSEngine/InitializeEPS` | Exact merchant transaction ID | AUTH token | Root `RedirectURL`; optional string `TransactionId`; `ErrorCode`, `ErrorMessage` |
| STATUS | GET `/EPSEngine/CheckMerchantTransactionStatus` | Same merchant transaction ID | AUTH token | Root `MerchantTransactionId`, `TotalAmount`, `Status`, `ErrorCode`, `ErrorMessage` |

The `x-hash` value is Base64(HMAC-SHA512(UTF8(hash key), UTF8(input))). Do not
Base64-decode the supplied key before signing. STATUS has the lower-case
`merchantTransactionId` query parameter and no request body. A future request
builder must encode query values without writing them to evidence logs.

AUTH body fields are exactly `userName`, `password`.

INITIALIZE body fields match the current integration's required subset:
`merchantId`, `storeId`, `CustomerOrderId`, `merchantTransactionId`,
`transactionTypeId`, `totalAmount`, `successUrl`, `failUrl`, `cancelUrl`,
`customerName`, `customerEmail`, `customerAddress`, `customerCity`, `customerState`,
`customerPostcode`, `customerCountry`, `customerPhone`, `productName`.

## Resolved reference inconsistencies

- The V4 transaction-type table defines Web as `1`, Android as `2`, iOS as `3`.
  Its example JSON and the supplied Postman body use `10`. The explicit Web table,
  user requirement and implemented integration agree on numeric `1`, which is
  enforced by this template and validator.
- V4 lists `merchantId` as mandatory. It is absent from the supplied Postman
  initialization example. The implemented EPS Technical Team-confirmed contract
  includes it; this template therefore requires an environment reference for it.
- The guide has a `merchantTransactonId` table typo and inconsistent casing in
  example customer fields. The collection and confirmed integration use
  `merchantTransactionId`; customer/product fields follow the integration's
  lower camel case, while `CustomerOrderId` retains its capital C/O/I.
- Optional Postman shipping/product-list/financial fields are not copied into the
  integration's required payload. No embedded credentials, IDs, hashes, JWTs or
  sample customer values are reused.

## Implemented offline request validation

`src/request-contract.mjs` validates concrete JSON documents with explicit private
context. It performs no request and returns fixed codes only. The typed JSON
template remains a plan; no runtime request builder or transport is implemented.

- POST URLs match their canonical constants exactly. STATUS uses the same exact
  base/path and exactly one `merchantTransactionId` query key, with no fragment,
  extra parameter, alias, duplicate or body. URL-normalization alternatives are
  rejected. Query values remain strings.
- JSON request key sets/casing are exact. INITIALIZE requires the eighteen fields
  listed above, Web type numeric `1`, numeric positive `totalAmount`, nonempty
  required strings and the original CustomerOrderId/merchantTransactionId/amount.
  Unreviewed optional fields and case aliases are rejected.
- HTTP header names are case-insensitive, but duplicate case variants are
  rejected. Prepared requests contain only `Content-Type: application/json`,
  `x-hash`, and (INITIALIZE/STATUS only) `Authorization`. Bearer binding must match
  the original token exactly. No token is required or permitted on AUTH.
- HMAC compares against the exact username or transaction ID using UTF-8 key and
  input and Base64 SHA-512 output. Hash keys are never Base64-decoded, and inputs
  are not trimmed. Test fixtures contain synthetic values only.
- Step 4 adds dedicated-origin/known-ecommerce-host checks and fixed diagnostic
  callback paths. These are toolkit policies, not a confirmed EPS callback
  procedure. Ownership, complete origin inventory, public reachability and
  callback authenticity remain unconfirmed; execution stays disabled.

## Implemented offline response validation

`src/response-contract.mjs` separates HTTP, JSON and business validation. Its
results include acceptance/outcome/code/paymentVerified only, never raw values.
Its parsed-payload helper assumes JSON size/depth/duplicate checks have already
been applied; a future runner must use the full `validateEpsResponse` envelope.

| Step | Acceptance rule |
| --- | --- |
| AUTH | Exact root `token`: nonempty bounded opaque Bearer token, no conflicting lower-case `errorCode`/`errorMessage` |
| INITIALIZE | Exact root `RedirectURL`: safe EPS HTTPS URL, no conflicting upper-case `ErrorCode`/`ErrorMessage`; optional absent/null or valid string `TransactionId` |
| STATUS | Exact root string `MerchantTransactionId` matches the original request; normalized `TotalAmount` matches the original positive amount; exact `Status` is `Success`; no conflicting upper-case error fields |

Common rules and explicit policies:

- HTTP must be an integer 200–299. HTTP 101 is HTTP_FAILURE, independently of
  gateway JSON `ErrorCode: 101` under HTTP 200, which is BUSINESS_FAILURE. HTTP 200
  alone never proves authentication, initialization or a completed payment.
- The body must be a valid UTF-8 JSON object, not null/array/scalar. Duplicate keys
  (including escaped duplicates), oversized documents and excess nesting fail.
- Known field casing aliases fail even when the canonical field is also present.
  Unknown extra response fields are ignored and never returned in diagnostics;
  they cannot substitute for required canonical fields.
- No-error code representations are absent, null, empty string or numeric zero;
  these retain the integration's no-error gate. String `"0"`, whitespace or any
  nonzero code is an error. Error messages may be absent/null/empty only. Malformed
  boolean/array/object error fields fail instead of relying on JavaScript truthiness.
- Money uses the integration's one-to-eight whole digits, optional one/two decimal
  digits, string or finite number; normalization pads cents without rounding.
  Negative, exponential-string, overprecision, non-JSON-object and mismatched
  amounts fail. Merchant transaction IDs are compared as exact strings, retaining
  leading zeros and never coerced from numbers.
- Nonempty statuses other than exact `Success`, including case/whitespace variants,
  `Failed` and `Cancelled`, remain PENDING with `accepted: false` and
  `paymentVerified: false`. No unconfirmed terminal mapping is inferred. Missing,
  blank or non-string Status is a business failure. Success plus any error fails.
- AUTH token is opaque: no JWT decoding/signature/expiry claim is made. Bearer
  token syntax excludes whitespace/control characters and invalid header-token
  punctuation. Token extraction into a future runner would remain private.

Toolkit policies stricter than the current ecommerce helper:

| Toolkit policy | Reason and source distinction |
| --- | --- |
| 32,768-byte JSON document limit, depth 32, duplicate-key rejection | Defensive offline parser limits; not claimed as EPS limits |
| Token at most 8,192 characters and Bearer syntax check | Header safety; app currently checks nonempty token and error fields only |
| Redirect at most 4,096 characters, standard HTTPS port, no whitespace/control/fragment | Additional URL safety; app already requires HTTPS, no userinfo and EPS host allowlist |
| Optional present TransactionId must be a nonblank string, at most 160 characters, without controls | Fails malformed values explicitly; app currently converts non-string values to null |
| CustomerOrderId at most 160 characters; no controls | Local reference safety cap, not a V4 maximum claim |
| Explicit error-field types and known alias rejection | Prevents malformed or conflicting payloads being treated as accepted |

The 20-second timeout plan follows the integration. These are offline checks;
transport deadlines, body limits and safe extraction are not wired to any client.

## Transaction uniqueness and correlation

V4 requires a unique merchant transaction ID (minimum ten decimal digits) and
unique CustomerOrderId for each new initialization. The integration restricts its
merchant ID to 10–30 digits and generates a 23-digit string using 13 timestamp
digits plus ten random decimal digits. That generator is probabilistic; format
validation alone cannot prove global uniqueness.

This toolkit generates no IDs in Step 2. `createIdentityRegistry` reserves both
IDs in memory, refuses reuse and has no automatic release. It is intended only
for future new-initialization planning, not STATUS. A new registry/process has no
history; no merchant-wide or restart-safe uniqueness guarantee is made. A future
initializer needs an approved private attempt ledger and must preserve the same
ID/amount/account binding after uncertain responses, never generate a replacement
ID merely to retry. No ledger/database is created here.

The API request's lower-case `merchantTransactionId` becomes the status response's
upper-case `MerchantTransactionId`. EPS `TransactionId` is a separate optional
bank reference, not a substitute query parameter. No ecommerce Payment/order is
created by this standalone project.

## Remaining unconfirmed execution requirements

1. Bank-approved Sandbox test account, allowed amount and assurance about test
   funds, credential scope, token lifetime/refresh rules and hosted-session expiry.
2. Completing the payment on the validated EPS hosted RedirectURL before expecting
   `Status: Success`. Immediate status after initialization may be unconfirmed.
3. A separate approved public-HTTPS callback receiver, exact callback method/body
   and query preservation, signature/correlation procedure and receiver ownership.
   Ecommerce callback signing is an app convention, not proof of an EPS signature
   standard. Existing ecommerce handlers can reconcile/settle stored payments and
   must not receive callbacks for unlinked standalone references.
4. Documented status polling/repeatability, rate limits, retry/backoff behavior and
   bank-side effects. A GET method or a function name does not prove side-effect
   guarantees. No automatic retries are enabled or authorized.
5. Recovery when an initialization response is lost, plus EPS-confirmed final
   failure/cancellation statuses. Never infer those states or initialize again
   while an existing attempt is uncertain.
6. A reviewed EPS transport/evidence implementation. Step 3 adds separate safe
   local capture probes; they do not exercise EPS requests or remote TCP/TLS.

All payment/trace/callback and payment-session capture execution remains disabled. Run `npm test` for
all local checks or `npm run test:contract` for the contract suite. Tests use
synthetic values and a socket/DNS/HTTP tripwire. Offline PASS does not establish
runtime Sandbox compatibility or authorize the next phase. The Step 3 readiness
command has a separate constrained DNS/local-capture scope documented in
[network-readiness.md](network-readiness.md).
Step 4's credential-free local profile and additional fail-closed policies are
documented in [execution-safety.md](execution-safety.md).

Step 5's process-only helper adds stricter synthetic preparation policy (23-digit
numeric candidate plus correlated CustomerOrderId, canonical BDT and fixed
synthetic profile) without changing EPS API request/response mapping. See
[private-environment.md](private-environment.md). Local checks do not establish
credential validity, callback approval or hosted-payment compatibility.
