<#
.SYNOPSIS
    Enrolls one prepared Windows test host against the EEOP Development environment, and proves the enrolled
    key works, in a single command.

.DESCRIPTION
    Run this only after EEOP-Gate4-Prepare.ps1 has reported PASSED on this host, and only once an enrollment
    token has been issued for it.

    The token is the one thing this script cannot fetch: the host holds no Azure credential, deliberately. So
    it is typed - or pasted - at a masked prompt, kept in memory as a SecureString, handed to the agent
    through the environment for the duration of one call, and cleared immediately afterwards whatever the
    outcome. It is never an argument, never written to a file, never echoed, and never recorded in the
    evidence.

    What the script does: verifies the installed binaries still match the approved artifact, confirms the host
    is configured and not yet enrolled, enrolls, clears the token, then runs `status` and `authcheck` as fresh
    processes - which is what proves the private key reloads from DPAPI after the enrolling process is gone.

    It does not install a Windows service and does not start heartbeat or inventory work.

.PARAMETER PlatformUri
    The platform to enroll against. Defaults to the Development ingestion API, and must match what the host
    was configured with.

.EXAMPLE
    PS> .\EEOP-Gate4-Enroll.ps1
#>

[CmdletBinding()]
param(
    [string] $PlatformUri = 'https://eeop-dev-ingestion-api.azurewebsites.net/'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# The one canonical agent build, the same values EEOP-Gate4-Prepare.ps1 extracted and EEOP-Gate5-Heartbeat.ps1
# reuses, recorded in canonical-agent.json and asserted identical across all three scripts by
# EEOP-CanonicalAgent.Tests.ps1. Checked again here because enrollment is the step that creates a private key:
# the binary that generates it has to be the approved one at that moment, not merely at preparation time.
$AgentCommit = 'ede0a4dbcc87c9bda6a63475acdee9fe0da2aa21'
$PackageName = 'eeop-agent-win-x64.zip'
$ExpectedPackageHash = '7fbbe2a61979776cec428c5502d45be6836d0c6e471e54ee1dfbadf51f14b02f'
$ExpectedBinaryHashes = [ordered]@{
    'eeop-agent.exe'     = '3016e8a182d1f5db8f91c6b19252941498d0abd1ec8b629134f2d2835d733450'
    'eeop-agent.dll'     = '89d202e17e71d5329222bb1dfbc2f17a6f2059fe4004462d5e34ad02866516c0'
    'EEOP.Contracts.dll' = 'fb9cf48c29fe168bd139a1dcb2e88c0bf5f7eb45d01c3003c4fc5a310a8e404b'
}
$ExpectedTokenLength = 43

$Root = 'C:\ProgramData\EEOP'
$WorkRoot = Join-Path $Root 'Gate4'
$InstallRoot = Join-Path $WorkRoot 'agent'
$ResultsPath = Join-Path $WorkRoot 'gate4-enrollment-results.txt'
$CredentialStore = Join-Path $Root 'Agent'

$RunId = 'GATE4E-{0:yyyyMMdd-HHmmss}Z-{1}' -f (Get-Date).ToUniversalTime(), $env:COMPUTERNAME
$results = [ordered]@{}
$failures = New-Object System.Collections.Generic.List[string]

function Add-Result {
    param([string] $Name, [string] $Value)
    $script:results[$Name] = $Value
}

function Add-Failure {
    param([string] $Description)
    $script:failures.Add($Description) | Out-Null
}

# Only the exception's own message, which the agent writes without secret values in it. No stack trace, no
# command line, no environment dump.
function Get-SafeError {
    param([System.Management.Automation.ErrorRecord] $ErrorRecord)
    return ($ErrorRecord.Exception.Message -replace '\s+', ' ').Trim()
}

function Get-Sha256 {
    param([string] $Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-ResultFile {
    param([bool] $Passed)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('EEOP Gate 4 - Windows device enrollment') | Out-Null
    $lines.Add(('generated: {0:u}' -f (Get-Date).ToUniversalTime())) | Out-Null
    $lines.Add('') | Out-Null
    foreach ($key in $script:results.Keys) {
        $lines.Add(('{0,-24}: {1}' -f $key, $script:results[$key])) | Out-Null
    }
    if ($script:failures.Count -gt 0) {
        $lines.Add('') | Out-Null
        $lines.Add('errors:') | Out-Null
        foreach ($failure in $script:failures) {
            $lines.Add("  - $failure") | Out-Null
        }
    }
    $lines.Add('') | Out-Null
    $lines.Add(('overall                 : {0}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }))) | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('This file is safe to share: it holds no token, private key, signature or credential. The') | Out-Null
    $lines.Add('device id it names is an identifier, not a secret.') | Out-Null

    New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
    # ASCII, and with a BOM, so the file reads identically in Notepad, an editor and a pasted transcript.
    Set-Content -Path $ResultsPath -Value $lines -Encoding UTF8
}

function Complete-Run {
    # Belt and braces: whatever happened above, the token does not outlive this script.
    Remove-Item Env:\EEOP_AGENT_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:\EEOP_AGENT_PLATFORM_URI -ErrorAction SilentlyContinue

    $passed = $script:failures.Count -eq 0
    Write-ResultFile -Passed $passed
    Write-Host ''
    if ($passed) {
        Write-Host 'EEOP Gate 4 enrollment PASSED'
    }
    else {
        Write-Host 'EEOP Gate 4 enrollment FAILED'
    }
    Write-Host "Reference: $script:RunId"
    Write-Host 'Results:'
    Write-Host $ResultsPath
    Write-Host ''
    Write-Host 'To send the results back, run either of:'
    Write-Host "  Get-Content $ResultsPath"
    Write-Host "  Get-Content $ResultsPath | Set-Clipboard"
    exit $(if ($passed) { 0 } else { 1 })
}

Add-Result 'reference' $RunId
Add-Result 'hostname' $env:COMPUTERNAME
Add-Result 'expected agent commit' $AgentCommit
Add-Result 'expected agent package' ('{0} (sha256 {1})' -f $PackageName, $ExpectedPackageHash)

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Failure 'This script must run from an elevated PowerShell; the credential store cannot otherwise be written.'
    Complete-Run
}

# ---------------------------------------------------------------------------------------------------------
# 1. The binaries that will generate the key.
# ---------------------------------------------------------------------------------------------------------

$agentExe = Join-Path $InstallRoot 'eeop-agent.exe'
if (-not (Test-Path -LiteralPath $agentExe)) {
    Add-Result 'binaries verified' 'no'
    Add-Failure ("$agentExe was not found. Run EEOP-Gate4-Prepare.ps1 on this host first.")
    Complete-Run
}

$mismatched = @()
foreach ($name in $ExpectedBinaryHashes.Keys) {
    $path = Join-Path $InstallRoot $name
    if (-not (Test-Path -LiteralPath $path)) {
        $mismatched += "$name is missing"
        continue
    }
    $actual = Get-Sha256 $path
    if ($actual -ne $ExpectedBinaryHashes[$name]) {
        $mismatched += "$name is $actual, expected $($ExpectedBinaryHashes[$name])"
    }
}
if ($mismatched.Count -gt 0) {
    Add-Result 'binaries verified' 'no'
    Add-Failure (('The installed binaries do not match the approved artifact {0}: {1}. Nothing was enrolled. ' -f
            $PackageName, ($mismatched -join '; ')) +
        'Re-run EEOP-Gate4-Prepare.ps1 from the same published set as this script, so both pin the same build.')
    Complete-Run
}
Add-Result 'binaries verified' ('yes ({0})' -f ($ExpectedBinaryHashes.Keys -join ', '))

# ---------------------------------------------------------------------------------------------------------
# 2. The host must be prepared and still unenrolled. Re-enrollment is a recovery token and an administrator's
#    decision, not something a convenience script does to a host that already holds a key.
# ---------------------------------------------------------------------------------------------------------

if (Test-Path -LiteralPath (Join-Path $CredentialStore 'credential.bin')) {
    Add-Result 'state before enrollment' 'already enrolled'
    Add-Failure ('This host already holds a device credential. Enrollment stops rather than disturbing it; ' +
        're-enrollment needs a device_recovery token.')
    Complete-Run
}

$statusBefore = (& $agentExe status 2>&1) -join ' '
if ($statusBefore -notmatch 'configuration loaded from') {
    Add-Result 'state before enrollment' 'not configured'
    Add-Failure ('The agent reports no usable configuration. Run EEOP-Gate4-Prepare.ps1 first: {0}' -f
        $statusBefore.Trim())
    Complete-Run
}
Add-Result 'state before enrollment' 'configured, not enrolled'

# ---------------------------------------------------------------------------------------------------------
# 3. The token. Masked at the prompt, and gone from this session before the script ends.
# ---------------------------------------------------------------------------------------------------------

Write-Host 'Paste the enrollment token. It will not be shown, logged or saved.'
$secureToken = Read-Host -AsSecureString -Prompt 'Enrollment token'
$plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))

if ([string]::IsNullOrWhiteSpace($plainToken) -or $plainToken -eq 'unset') {
    $plainToken = $null
    Add-Result 'token accepted' 'no'
    Add-Failure ("No token was entered, or the Key Vault placeholder value 'unset' was entered, which means " +
        'a deployment has overwritten the delivery. Have a fresh token issued.')
    Complete-Run
}
if ($plainToken.Length -ne $ExpectedTokenLength) {
    Add-Result 'token accepted' 'no'
    Add-Failure ('The value entered is {0} characters; an enrollment token is {1}. Nothing was sent.' -f
        $plainToken.Length, $ExpectedTokenLength)
    $plainToken = $null
    Complete-Run
}
Add-Result 'token accepted' ('yes ({0} characters, not the placeholder)' -f $ExpectedTokenLength)

# ---------------------------------------------------------------------------------------------------------
# 4. Enroll. One attempt: the token is single-use, so a retry loop would burn it and prove nothing.
# ---------------------------------------------------------------------------------------------------------

$enrollOutput = ''
$enrollExit = -1
try {
    $env:EEOP_AGENT_PLATFORM_URI = $PlatformUri
    $env:EEOP_AGENT_ENROLLMENT_TOKEN = $plainToken
    $enrollOutput = (& $agentExe enroll 2>&1) -join ' '
    $enrollExit = $LASTEXITCODE
}
catch {
    Add-Result 'enrollment' 'failed'
    Add-Failure ('enroll could not be run: {0}' -f (Get-SafeError $_))
}
finally {
    Remove-Item Env:\EEOP_AGENT_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    $plainToken = $null
    $secureToken.Dispose()
    [GC]::Collect()
}

# Defensive: the agent does not echo the token, and nothing below should be able to carry it, but the
# transcript of a failed call is the one place a surprise would surface.
$enrollOutput = $enrollOutput.Trim()

if ($enrollExit -ne 0) {
    Add-Result 'enrollment' ('failed (exit {0})' -f $enrollExit)
    if ($enrollExit -eq 75) {
        Add-Failure ('The platform was unreachable or rate limited, so the token was not consumed and can ' +
            'be reused: {0}' -f $enrollOutput)
    }
    else {
        Add-Failure ('The platform refused the enrollment, and does not say why. Check the token has not ' +
            'expired, been used already, or been issued for another site: {0}' -f $enrollOutput)
    }
    Complete-Run
}

if ($enrollOutput -match 'device\s+([0-9a-fA-F-]{36})') {
    Add-Result 'device id' $Matches[1]
}
Add-Result 'enrollment' 'accepted'

# ---------------------------------------------------------------------------------------------------------
# 5. A fresh process reads the key back, which is the restart proof: this is not the process that enrolled.
# ---------------------------------------------------------------------------------------------------------

$statusOutput = (& $agentExe status 2>&1) -join ' '
$statusExit = $LASTEXITCODE
if ($statusExit -eq 0 -and $statusOutput -match 'enrolled as device') {
    Add-Result 'status after enrollment' 'enrolled (key reloaded by a new process)'
}
else {
    Add-Result 'status after enrollment' ('not enrolled (exit {0})' -f $statusExit)
    Add-Failure ('status did not report an enrolled host after enrollment: {0}' -f $statusOutput.Trim())
}

try {
    Add-Result 'credential store acl' (Get-Acl -Path $CredentialStore).Sddl
}
catch {
    Add-Result 'credential store acl' ('unavailable: {0}' -f (Get-SafeError $_))
}

$stored = @(Get-ChildItem -LiteralPath $CredentialStore -File -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name | Sort-Object)
Add-Result 'credential store files' ($stored -join ', ')

# ---------------------------------------------------------------------------------------------------------
# 6. One signed request, which is what the whole gate exists to prove.
# ---------------------------------------------------------------------------------------------------------

$authOutput = (& $agentExe authcheck 2>&1) -join ' '
$authExit = $LASTEXITCODE
if ($authExit -eq 0 -and $authOutput -match 'accepted this device') {
    Add-Result 'signed request' 'accepted by the platform'
    if ($authOutput -match 'clock difference against the platform:\s*(-?[0-9.]+)s') {
        Add-Result 'clock difference' ('{0}s' -f $Matches[1])
    }
}
else {
    Add-Result 'signed request' ('refused (exit {0})' -f $authExit)
    Add-Failure ('The signed request was not accepted: {0}' -f $authOutput.Trim())
}

Complete-Run
