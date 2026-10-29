# EPS Step 3 network and packet capture readiness

This step checks the Windows workstation for future EPS Sandbox diagnostics. It
does not execute AUTH, INITIALIZE, STATUS, callbacks or database work. The EPS
request plans are unchanged. `execution.networkEnabled`, payment requests,
automatic retries and the future payment capture flag remain disabled.

## Commands and scope

```powershell
Set-Location E:\Ecommerce\General\deshiplus_eps_trace
npm run validate
npm test
npm run interfaces
npm run readiness
```

`npm test` uses a network-denial preloader. Its readiness tests use synthetic
PCAPNG headers, fake capture processes and mocked DNS/filter compilation.

`npm run readiness` is an explicit real local diagnostic. It:

1. Reads Node/npm/TShark/dumpcap/Npcap versions and Npcap driver state. The local
   PowerShell helper reads adapter identity, driver version, elevation and the
   Npcap AdminOnly setting; it does not read IP/MAC addresses, credentials or .env.
2. Lists TShark interfaces and matches index 5's NPF GUID to Windows's active
   Wi-Fi adapter. A friendly name alone is insufficient. An index/GUID mismatch,
   disconnected Wi-Fi, unavailable tools or capture permission failure fails.
3. Resolves only `sandboxpgapi.eps.com.bd` using the system DNS resolver. This is
   a DNS lookup, not an EPS TCP/TLS/API request. The report records family/count,
   not the workstation's IP address or an API response.
4. Uses `dumpcap -i 5 -f "tcp port 443 and host sandboxpgapi.eps.com.bd" -d` to
   compile the intended filter and quit. The hostname in this filter can cause
   DNS resolution. No packet capture starts for this filter. The broad HTTPS/DNS
   template filter was narrowed to EPS HTTPS only; this does not change API plans.
5. Opens interface 5 for a bounded permission probe using only `less 1`.
   No complete Ethernet/Wi-Fi frame can satisfy this length filter. The resulting
   PCAPNG must be readable and contain zero packets, or the probe fails.
6. Starts a separate Npcap Loopback capture restricted to IPv4 TCP between
   127.0.0.1 and 127.0.0.1 on one newly allocated local listener port. Only after
   a capture-open banner AND complete PCAPNG section/interface blocks are present
   does it create three local TCP connections. Neither endpoint sends application
   payload. No EPS hostname/address is used for a TCP connection.
7. Waits for TShark's bounded capture to stop gracefully. If readiness fails or a
   watchdog expires, only the owned capture process tree is terminated. No capture
   process is intentionally left running. A failed probe is not silently skipped.
8. Reads the files with TShark name resolution disabled, checks PCAPNG format,
   packet counts, exactly three TCP streams, loopback/port scope, zero application
   payload and valid monotonic timestamps within the run window.

`npm run readiness:local` performs the same local tool/permission/loopback checks
but skips EPS DNS and intended-filter compilation. Its report explicitly marks
that scope as not requested; local PASS cannot be cited as a DNS/filter PASS.
`npm run doctor` remains a quick version/config check and never starts capture.

## Artifacts

Each invocation creates a fresh timestamp/UUID directory below
`evidence/readiness/`, which is ignored by Git:

| File | Content |
| --- | --- |
| `readiness-report.json` | Tool versions, interface names/identity, DNS/filter results, capture state/counts/timestamps and fixed failure codes |
| `wifi-permission.pcapng` | Empty interface-5 permission evidence; no complete live frames |
| `session.pcapng` | Synthetic payload-free loopback TCP only; not EPS payment evidence |

No credentials, JWTs, x-hash values, customer data, raw process errors or arbitrary
environment values enter the report. Child tools receive a narrow OS environment
allowlist, not EPS/database/auth credentials or key-log settings. TLS key logging,
TLS bypass, raw request/response body/header recording and payment capture
enablement are rejected. PCAP files contain network metadata and should still be
kept internal. No TLS key collector or HTTP/TLS client exists in this project.

`Get-LocalCaptureEnvironment.ps1` checks both normal and WOW6432Node Npcap registry
locations because installations differ. Actual permission is established by the
successful adapter-open probe, not by elevation or the registry flag alone.
Existing artifacts are not overwritten. A new failure produces FAIL with fixed
codes; raw third-party error messages are suppressed.

## What a PASS proves

The current terminal token can open the identified Wi-Fi adapter without
collecting unrelated packets, and the local capture stack can preserve/read
synthetic PCAPNG packets with valid timestamps. It does not prove delivery of
live Wi-Fi traffic, EPS port 443 reachability, TLS/certificate negotiation, proxy
or firewall compatibility, credentials, API/business behavior or payment success.
DNS answers, adapter indices, network and terminal privileges may change and
must be checked again before an authorized future test.

Remaining execution prerequisites include an EPS transport/evidence runner,
approved test credentials/account/amount, safe hosted-payment/callback procedure,
merchant-wide correlation/uniqueness and confirmed retry/status-polling behavior.
`npm run trace` stays disabled. Stop after Step 3.
