# eeop-agent-dist

Public distribution of the EEOP Windows agent **test** artifacts, so a dedicated internal test host can fetch
them over plain HTTPS with no credential of any kind and verify them against published hashes.

This repository holds artifacts only. The source lives in the private `eeop-platform` repository, and nothing
here is a product release: these builds exist to prove one controlled enrollment against the Development
environment. **Not for a customer or production system.**

## Why anything is public

The test host must download the agent without holding a GitHub token, an Azure credential or any other
reusable secret — a machine that is about to hold a device private key should carry as few credentials as
possible. Publishing the artifact and pinning its hash achieves that: the download needs no authority, and
integrity comes from the hash rather than from the transport or the hosting account.

Nothing published here contains a secret. The agent binaries hold no token, no key, no credential, no
connection string and no environment-specific configuration; the platform address is supplied on the host at
`configure` time and stored there. The only sensitive material in the enrollment flow — the enrollment token
and the device private key — never leaves the operator's session and the device respectively.

## Contents

| File | Purpose |
| --- | --- |
| `EEOP-Gate4-Prepare.ps1` | Prepares one Windows test host for the Gate 4 enrollment, and stops before it |
| `eeop-agent-win-x64.zip` | The self-contained `win-x64` agent, published as a release asset |
| `SHA256SUMS.txt` | The pinned hashes the script and the operator verify against |

`eeop-agent-win-x64.zip` is attached to the release rather than committed, because a 34 MB binary in Git
history is a cost that never goes away.

## Verifying

Everything is pinned twice: the caller pins the script's hash before running it, and the script pins the
package's and the binaries' hashes before extracting or executing anything. A mismatch stops the run; the
script never proceeds on an unverified artifact.

```powershell
(Get-FileHash .\EEOP-Gate4-Prepare.ps1 -Algorithm SHA256).Hash.ToLower()
(Get-FileHash .\eeop-agent-win-x64.zip  -Algorithm SHA256).Hash.ToLower()
```

Verify `eeop-agent.dll` as well as `eeop-agent.exe`: the `.exe` is the generic .NET apphost launcher and
carries none of this project's code, so its hash alone would not detect a substituted payload.

## What the script does not do

It does not enroll a device, does not provision or read an enrollment token, does not install a Windows
service, does not start heartbeat or inventory work, and requires no .NET SDK, no .NET runtime and no Azure
CLI. It writes one sanitized results file and uploads nothing.
