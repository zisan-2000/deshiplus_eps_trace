# Step 7C EPS Sandbox AUTH-only diagnostic

`npm run auth:check` is an independent, one-request command. It requires the
operator to type `AUTH-ONLY`. After capture readiness, PowerShell loads the three
AUTH values from the protected project-root `.env.local`; any missing value is
requested through a hidden prompt. A nonempty process environment value is allowed
only when the matching file value is empty or identical. Conflicts fail closed.
Only the three AUTH values are copied into the child Node process environment and
the PowerShell references are cleared after launch. Merchant/store values are not
passed to the AUTH child.

The command can make exactly one request:

```text
POST https://sandboxpgapi.eps.com.bd/v1/Auth/GetToken
Content-Type: application/json
x-hash: Base64(HMAC-SHA512(UTF8(username), UTF8(hash key)))
```

It cannot call INITIALIZE, STATUS, a hosted page or callbacks. It has no retry.
The regular `npm run trace` and CLI `auth`, `initialize`, `status` and `run`
commands remain blocked.

PowerShell owns all TShark processes. It runs interface inventory, starts the
capture, and requires Interface 5 to be listed as `Wi-Fi`, the TShark process to
remain running, and a complete PCAPNG Section Header Block plus Interface
Description Block before it starts the Node AUTH runner. A captured packet is
not required: TShark writes those two structural blocks when capture is ready.
The redirected `Capturing on` stderr line is recorded only as a sanitized
diagnostic because pipe buffering can delay its observer. Node never spawns
TShark. The fixed filter is
`tcp port 443 and host sandboxpgapi.eps.com.bd`. Inventory, launch, or readiness
failure aborts with `requestDisposition: NOT_SENT` before HTTP execution.

Evidence is written below `evidence/auth-check/<session>/` as
`combined-report.json` and `session.pcapng`. JSON includes `failureStage`,
`requestDisposition` (`NOT_SENT`, `UNCERTAIN`, or `SENT`), the HTTP status, the
sanitized AUTH result, and any available DNS/TCP/TLS/first-byte/total timing.
`captureDiagnostics` records only booleans, bounded counts, elapsed time and the
readiness state; it never stores raw stderr, interface inventory text or packet
payloads.
Credentials, `x-hash`, token, response body and provider error message are
excluded. TLS key logging and raw payload reporting stay disabled.

Run the local test first:

```powershell
cd E:\Ecommerce\General\deshiplus_eps_trace
npm test
npm run auth:mock-evidence
```

Populate the already Git-ignored `.env.local` locally:

```dotenv
EPS_USERNAME=
EPS_PASSWORD=
EPS_HASH_KEY=
EPS_MERCHANT_ID=
EPS_STORE_ID=
```

Values are literal: everything after the first `=` is preserved, so passwords
and hash keys may contain spaces, `#`, `$`, quotes, semicolons and additional `=`
characters. Do not wrap a value in quotes unless those quotes are part of it. The
file must keep its restricted Windows ACL. If it is replaced rather than edited
in place, reapply protection from the project root:

```powershell
Import-Module .\scripts\AuthCredentialLoader.psm1 -Force
Protect-EpsCredentialFile -Path .\.env.local
```

After explicit authorization for one EPS Sandbox AUTH request:

```powershell
cd E:\Ecommerce\General\deshiplus_eps_trace
npm run auth:check
```

Type `AUTH-ONLY` at the confirmation prompt. Only values missing from both the
file and process environment are requested through hidden prompts. Do not run
`npm run trace`.
