# eeop-agent-dist

Public distribution of the EEOP Windows agent **test** artifacts, so a dedicated internal test host can fetch
them over plain HTTPS with no credential of any kind and verify them against published hashes.

This repository holds artifacts only. The source lives in the private `eeop-platform` repository, and nothing
here is a product release: these builds exist to prove one controlled enrollment, and then one controlled
heartbeat validation, against the Development environment. **Not for a customer or production system.**

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
| `EEOP-Gate4-Enroll.ps1` | Enrolls that prepared host, then proves the enrolled key with one signed request |
| `EEOP-Gate5-Heartbeat.ps1` | Runs the real heartbeat worker on that enrolled host: first beats, restart, silence past the offline threshold, recovery |
| `eeop-agent-win-x64.zip` | The self-contained `win-x64` agent, published as a release asset |
| `SHA256SUMS.txt` | The pinned hashes the scripts and the operator verify against |

`eeop-agent-win-x64.zip` is attached to the release rather than committed, because a 34 MB binary in Git
history is a cost that never goes away. There is one package per gate, under the same name and with different
hashes: the Gate 4 build (`gate4-fcea97b`) has no heartbeat worker in it, and the Gate 5 build
(`gate5-ede0a4d`) is what the heartbeat script installs, beside the Gate 4 one rather than over it.

## Verifying

Everything is pinned twice: the caller pins the script's hash before running it, and the script pins the
package's and the binaries' hashes before extracting or executing anything. A mismatch stops the run; the
script never proceeds on an unverified artifact.

```powershell
(Get-FileHash .\EEOP-Gate4-Prepare.ps1    -Algorithm SHA256).Hash.ToLower()
(Get-FileHash .\EEOP-Gate4-Enroll.ps1     -Algorithm SHA256).Hash.ToLower()
(Get-FileHash .\EEOP-Gate5-Heartbeat.ps1  -Algorithm SHA256).Hash.ToLower()
(Get-FileHash .\eeop-agent-win-x64.zip    -Algorithm SHA256).Hash.ToLower()
```

Verify `eeop-agent.dll` as well as `eeop-agent.exe`: the `.exe` is the generic .NET apphost launcher and
carries none of this project's code, so its hash alone would not detect a substituted payload.

## What the scripts do not do

No script provisions a token, installs a Windows service, collects inventory, or requires a .NET SDK, a .NET
runtime or the Azure CLI. Each writes one sanitized results file and uploads nothing.

The preparation script does not enroll. The enrollment script does enroll, but it cannot fetch a token: the
token is typed at a masked prompt, held only for the duration of one call, and never written to a file, an
argument or the results.

The heartbeat script is the mirror image of that: it refuses to run unless the host is **already** enrolled as
the device it expects, and it never calls `enroll`. It runs the agent's real `run` host — the same runtime the
Windows Service hosts — kills it, waits out the platform's offline threshold and starts it again, and leaves
the host with no agent running and no service installed. It cannot see a device's `online` or `offline` state,
because that is the platform's judgment and not the agent's; what it records is the UTC windows the platform's
own history is then read against.

Its results file carries identifiers, states, UTC timestamps, sequence numbers, hash verdicts and counts. The
agent's per-phase log stays on the host, and the script scans it for key, signature, header and token markers
before reporting either way.
