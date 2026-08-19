<#
.SYNOPSIS
    Proves heartbeat, restart and offline recovery on one already-enrolled Windows test host, in a single
    command.

.DESCRIPTION
    Run this only on the host that passed Gate 4, and only against the Development environment. It changes no
    identity: the device this host already is, and the credential it already holds, are what it uses.

    The script uses the canonical agent build that Gate 4 preparation already installed - the same package
    serves both gates - verifies it against published hashes, confirms this host is already enrolled as the
    expected device, and then runs the real agent runtime, the same `run` path the Windows Service uses, in
    four phases:

      A  first heartbeat      the agent runs until the platform has accepted two beats
      B  restart              the agent is terminated and started again, with no re-enrollment
      C  offline              the agent stays stopped for longer than the platform's offline threshold
      D  recovery             the agent is started again and beats are accepted once more

    Offline is not something the agent decides or reports, so phase C produces one thing on this side: the
    exact window in which this host sent nothing. The transition itself is the platform's, and is read from the
    database afterwards.

    What it never does: enroll, re-enroll, install or start a Windows Service, collect inventory, or write a
    private key, signature, Authorization header or heartbeat body anywhere. The agent's own log is captured at
    debug level, which is categories, states, device ids and counts by construction, and the script scans that
    capture for sensitive markers before it reports.

    The host is left as it was found: the agent is not running when the script exits, and nothing is installed.

.PARAMETER ExpectedDeviceId
    Required. The device this host must already be, as the server-side enrollment evidence reports it. There is
    deliberately no default: the device a host is expected to be belongs to the run being authorized, not to
    the script, and a stale default is how a test ends up asserting a machine that no longer exists. The run
    stops before the agent is started if this host reports any other device.

.PARAMETER PackagePath
    Path to an already-downloaded eeop-agent-win-x64.zip. By default the script downloads the pinned public
    artifact.

.PARAMETER OfflineWaitSeconds
    How long phase C keeps the host silent. The default exceeds the platform's five-minute offline threshold
    plus one sweep period, and shortening it will not prove the transition.

.EXAMPLE
    PS> .\EEOP-Gate5-Heartbeat.ps1 -ExpectedDeviceId <the device id the enrollment evidence reported>
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [ValidateScript({
        if ($_ -eq '00000000-0000-0000-0000-000000000000') {
            throw 'ExpectedDeviceId must be a real device id, not an empty one.'
        }
        $true
    })]
    [string] $ExpectedDeviceId,
    [string] $PackagePath,
    [int] $OfflineWaitSeconds = 360
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# The canonical agent build, which Gate 4 preparation installs and this reuses, pinned the same way in both:
# the package hash before extraction, the binary hashes before execution.
$AgentCommit = '524a91569bc88a2a4b2af256ae225c4b4bcdccc4'
$PackageName = 'eeop-agent-win-x64.zip'
$PackageUrl = 'https://github.com/QOS-Holdings/eeop-agent-dist/releases/download/ws3b-524a915/eeop-agent-win-x64.zip'
$ExpectedPackageHash = '661b372924c6f9a4ad31f7a95c7e19890cc8b4cb75d8828b850d1c0ee9062e85'
$ExpectedBinaryHashes = [ordered]@{
    'eeop-agent.exe'     = '5d623126326792d04bb26ac5455d3a5c68443c7effb6b3911778b89cadaaf04e'
    'eeop-agent.dll'     = 'f6b40e3a1cd25d43982aaed67248215428a7d680b70823344fd1e78b01f62c5a'
    'EEOP.Contracts.dll' = 'aba8ec90b3afab30bf1e33b587d27d1dc4ab22c88dc87f3f455e72c7edeae263'
}

$Root = 'C:\ProgramData\EEOP'
$WorkRoot = Join-Path $Root 'Gate5'
$InstallRoot = Join-Path $WorkRoot 'agent'
$LogRoot = Join-Path $WorkRoot 'logs'
$ResultsPath = Join-Path $WorkRoot 'gate5-heartbeat-results.txt'
$CredentialStore = Join-Path $Root 'Agent'
$SequenceFile = Join-Path $CredentialStore 'heartbeat.json'

# What the agent writes when the platform accepted a beat, and when it loaded this host's identity. Both are
# debug-level lines from the agent's own audited log surface.
$AcceptedPattern = 'Heartbeat accepted; the platform holds this device as (?<status>\w+) at a (?<interval>\d+)s interval'
$IdentityPattern = 'enrolled as device (?<device>[0-9a-fA-F-]{36})'
# Anything that would mean the capture is not safe to keep. None of these can be produced by the agent's log
# messages; they are checked because "cannot happen" is worth verifying when the output is evidence.
$SensitiveMarkers = @('Authorization', 'EEOP-Device', 'BEGIN PRIVATE KEY', 'BEGIN EC PRIVATE KEY', 'signature=', 'nonce=')

$RunId = 'GATE5H-{0:yyyyMMdd-HHmmss}Z-{1}' -f (Get-Date).ToUniversalTime(), $env:COMPUTERNAME
$results = [ordered]@{}
$failures = New-Object System.Collections.Generic.List[string]
$agentProcess = $null

function Add-Result {
    param([string] $Name, [string] $Value)
    $script:results[$Name] = $Value
}

function Add-Failure {
    param([string] $Description)
    $script:failures.Add($Description) | Out-Null
}

function Get-SafeError {
    param([System.Management.Automation.ErrorRecord] $ErrorRecord)
    return ($ErrorRecord.Exception.Message -replace '\s+', ' ').Trim()
}

function Get-Sha256 {
    param([string] $Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Utc {
    return (Get-Date).ToUniversalTime()
}

function Format-Utc {
    param([datetime] $Moment)
    return '{0:yyyy-MM-ddTHH:mm:ssZ}' -f $Moment
}

function Write-ResultFile {
    param([bool] $Passed)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('EEOP Gate 5C - Windows device heartbeat, restart and offline recovery') | Out-Null
    $lines.Add(('generated: {0:u}' -f (Get-Utc))) | Out-Null
    $lines.Add('') | Out-Null
    foreach ($key in $script:results.Keys) {
        $lines.Add(('{0,-30}: {1}' -f $key, $script:results[$key])) | Out-Null
    }
    if ($script:failures.Count -gt 0) {
        $lines.Add('') | Out-Null
        $lines.Add('errors:') | Out-Null
        foreach ($failure in $script:failures) {
            $lines.Add("  - $failure") | Out-Null
        }
    }
    $lines.Add('') | Out-Null
    $lines.Add(('overall                       : {0}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }))) | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('This file is safe to share: it holds no private key, signature, Authorization header, token or') | Out-Null
    $lines.Add('heartbeat body. The device id and the credential digest it names are identifiers, not secrets.') | Out-Null

    New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
    Set-Content -Path $ResultsPath -Value $lines -Encoding UTF8
}

function Stop-Agent {
    param([string] $Phase)

    if ($null -eq $script:agentProcess) {
        return
    }

    $process = $script:agentProcess
    $script:agentProcess = $null
    try {
        if (-not $process.HasExited) {
            # Terminated rather than asked politely: a console process has no service control manager to stop
            # it, and an abrupt end is the harder case anyway - the sequence counter and the credential store
            # have to survive one.
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            $process.WaitForExit(15000) | Out-Null
        }
    }
    catch {
        Add-Failure ('{0}: the agent process could not be stopped: {1}' -f $Phase, (Get-SafeError $_))
    }
}

function Complete-Run {
    Stop-Agent -Phase 'cleanup'
    Remove-Item Env:\Logging__LogLevel__EEOP -ErrorAction SilentlyContinue
    Remove-Item Env:\Logging__LogLevel__Default -ErrorAction SilentlyContinue
    Remove-Item Env:\Logging__LogLevel__Microsoft -ErrorAction SilentlyContinue
    Remove-Item Env:\Logging__Console__FormatterName -ErrorAction SilentlyContinue
    Remove-Item Env:\Logging__Console__FormatterOptions__TimestampFormat -ErrorAction SilentlyContinue
    Remove-Item Env:\Logging__Console__FormatterOptions__UseUtcTimestamp -ErrorAction SilentlyContinue

    $passed = $script:failures.Count -eq 0
    Write-ResultFile -Passed $passed
    Write-Host ''
    if ($passed) {
        Write-Host 'EEOP Gate 5C heartbeat validation PASSED'
    }
    else {
        Write-Host 'EEOP Gate 5C heartbeat validation FAILED'
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

function Resolve-AgentPackage {
    if ($PackagePath) {
        if (-not (Test-Path -LiteralPath $PackagePath)) {
            throw "The package $PackagePath was not found."
        }
        return (Resolve-Path -LiteralPath $PackagePath).Path
    }

    # The package Gate 4 preparation downloaded. Since both gates pin the same canonical build, reusing it
    # means the host holds one agent package rather than two copies of the same bytes - and it is admitted by
    # the hash below either way, so reuse trusts the file no more than a fresh download would.
    $prepared = Join-Path (Join-Path $Root 'Gate4') $PackageName
    if (Test-Path -LiteralPath $prepared) {
        Write-Host 'using the agent package Gate 4 preparation downloaded'
        return (Resolve-Path -LiteralPath $prepared).Path
    }

    $destination = Join-Path $WorkRoot $PackageName
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $PackageUrl -OutFile $destination -UseBasicParsing -TimeoutSec 300
    return $destination
}

# Starts the agent runtime and returns once it is running. The agent's own log is the evidence, so it is
# captured to a file per phase, at debug level for this project's categories only.
function Start-Agent {
    param([string] $Phase)

    $out = Join-Path $LogRoot "$Phase.log"
    $err = Join-Path $LogRoot "$Phase.err.log"
    Remove-Item -LiteralPath $out, $err -ErrorAction SilentlyContinue

    $env:Logging__LogLevel__Default = 'Information'
    $env:Logging__LogLevel__Microsoft = 'Warning'
    $env:Logging__LogLevel__EEOP = 'Debug'
    # The default console formatter writes the timestamp and category on one line and the message on the
    # next, which is why the cadence below is read from each match's preceding line rather than its own.
    $env:Logging__Console__FormatterName = 'simple'
    $env:Logging__Console__FormatterOptions__TimestampFormat = 'yyyy-MM-ddTHH:mm:ssZ '
    $env:Logging__Console__FormatterOptions__UseUtcTimestamp = 'true'

    $script:agentProcess = Start-Process -FilePath (Join-Path $InstallRoot 'eeop-agent.exe') `
        -ArgumentList 'run' -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    return $out
}

# Waits until the capture holds the wanted number of accepted beats, or the budget runs out.
function Wait-ForAcceptedBeats {
    param([string] $LogPath, [int] $Count, [int] $TimeoutSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $found = @(Select-String -Path $LogPath -Pattern $AcceptedPattern -Context 1, 0 -ErrorAction SilentlyContinue)
        if ($found.Count -ge $Count) {
            return $found
        }
        if ($null -ne $script:agentProcess -and $script:agentProcess.HasExited) {
            return @(Select-String -Path $LogPath -Pattern $AcceptedPattern -Context 1, 0 -ErrorAction SilentlyContinue)
        }
    }
    return @(Select-String -Path $LogPath -Pattern $AcceptedPattern -Context 1, 0 -ErrorAction SilentlyContinue)
}

function Get-StoredSequence {
    if (-not (Test-Path -LiteralPath $SequenceFile)) {
        return $null
    }
    try {
        return [int64](Get-Content -LiteralPath $SequenceFile -Raw | ConvertFrom-Json).sequence
    }
    catch {
        return $null
    }
}

function Get-CredentialFingerprint {
    $file = Join-Path $CredentialStore 'credential.bin'
    if (-not (Test-Path -LiteralPath $file)) {
        return $null
    }
    $item = Get-Item -LiteralPath $file
    return [pscustomobject]@{
        Digest = Get-Sha256 $file
        Written = $item.LastWriteTimeUtc
        Length = $item.Length
    }
}

# One phase: run the agent, wait for beats, record what the platform said and what the counter did.
function Invoke-Phase {
    param(
        [string] $Phase,
        [string] $Label,
        [int] $Beats,
        [int] $TimeoutSeconds
    )

    $startedAt = Get-Utc
    $log = Start-Agent -Phase $Phase
    $accepted = Wait-ForAcceptedBeats -LogPath $log -Count $Beats -TimeoutSeconds $TimeoutSeconds
    $sequence = Get-StoredSequence
    $alive = $null -ne $script:agentProcess -and -not $script:agentProcess.HasExited
    Stop-Agent -Phase $Phase

    $reported = @()
    $intervals = @()
    $stamps = @()
    foreach ($match in $accepted) {
        $reported += $match.Matches[0].Groups['status'].Value
        $intervals += [int] $match.Matches[0].Groups['interval'].Value

        # The logger's own timestamp, on the line above the message.
        $preceding = @($match.Context.PreContext)
        if ($preceding.Count -gt 0 -and
            $preceding[-1] -match '^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)') {
            $stamps += [datetime]::Parse($Matches[1]).ToUniversalTime()
        }
    }

    $identity = @(Select-String -Path $log -Pattern $IdentityPattern -AllMatches -ErrorAction SilentlyContinue)
    $device = if ($identity.Count -gt 0) { $identity[0].Matches[0].Groups['device'].Value } else { '' }

    # Cadence, measured from the capture's own UTC timestamps rather than assumed from configuration.
    $cadence = ''
    if ($stamps.Count -ge 2) {
        $gaps = @(1..($stamps.Count - 1) | ForEach-Object { [int]($stamps[$_] - $stamps[$_ - 1]).TotalSeconds })
        $cadence = ($gaps -join ', ') + 's between accepted beats'
    }

    return [pscustomobject]@{
        Phase = $Phase
        Label = $Label
        StartedAt = $startedAt
        StoppedAt = Get-Utc
        Log = $log
        Accepted = $reported.Count
        Statuses = ($reported | Select-Object -Unique) -join ', '
        Intervals = ($intervals | Select-Object -Unique) -join ', '
        Sequence = $sequence
        Device = $device
        Alive = $alive
        Cadence = $cadence
    }
}

Add-Result 'reference' $RunId
Add-Result 'hostname' $env:COMPUTERNAME
Add-Result 'expected agent commit' $AgentCommit

$identityPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identityPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Failure 'This script must run from an elevated PowerShell; the credential store cannot otherwise be read.'
    Complete-Run
}

New-Item -ItemType Directory -Force -Path $WorkRoot, $InstallRoot, $LogRoot | Out-Null

# ---------------------------------------------------------------------------------------------------------
# 1. Nothing else may be beating for this device: two agents would share one counter and refuse each other.
# ---------------------------------------------------------------------------------------------------------

$service = Get-Service -Name 'EEOPAgent' -ErrorAction SilentlyContinue
if ($null -ne $service -and $service.Status -ne 'Stopped') {
    Add-Result 'agent service' ('present and {0}' -f $service.Status)
    Add-Failure ('The EEOPAgent service is {0} on this host. Two agents would share one sequence counter, so ' +
        'this test stops rather than competing with it.' -f $service.Status)
    Complete-Run
}
Add-Result 'agent service' $(if ($null -eq $service) { 'not installed (expected)' } else { 'installed, stopped' })

$running = @(Get-Process -Name 'eeop-agent' -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Add-Result 'agent processes' ('{0} already running' -f $running.Count)
    Add-Failure 'An eeop-agent process is already running on this host. Stop it and run this again.'
    Complete-Run
}
Add-Result 'agent processes' 'none running before the test'

# ---------------------------------------------------------------------------------------------------------
# 2. The Gate 5 build, verified before and after extraction.
# ---------------------------------------------------------------------------------------------------------

try {
    $package = Resolve-AgentPackage
}
catch {
    Add-Result 'agent package' 'not available'
    Add-Failure (Get-SafeError $_)
    Complete-Run
}

$packageHash = Get-Sha256 $package
if ($packageHash -ne $ExpectedPackageHash) {
    Add-Result 'artifact hash verified' 'no'
    Add-Failure ('The package SHA-256 is {0}; the approved artifact is {1}. Nothing was extracted.' -f
        $packageHash, $ExpectedPackageHash)
    Complete-Run
}
Add-Result 'artifact hash verified' ('yes (sha256 {0})' -f $packageHash)

try {
    Get-ChildItem -LiteralPath $InstallRoot -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
    Expand-Archive -LiteralPath $package -DestinationPath $InstallRoot -Force
}
catch {
    Add-Failure ('The package could not be extracted: {0}' -f (Get-SafeError $_))
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
    Add-Failure ('The installed binaries do not match the approved artifact: {0}. The agent was not run.' -f
        ($mismatched -join '; '))
    Complete-Run
}
Add-Result 'binaries verified' ('yes ({0})' -f ($ExpectedBinaryHashes.Keys -join ', '))

$agentExe = Join-Path $InstallRoot 'eeop-agent.exe'

# ---------------------------------------------------------------------------------------------------------
# 3. This host must already be the expected device. Nothing here enrolls, so an unenrolled or unexpected host
#    is a stop, not something to correct.
# ---------------------------------------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath (Join-Path $CredentialStore 'credential.bin'))) {
    Add-Result 'enrollment state' 'not enrolled'
    Add-Failure 'This host holds no device credential. Gate 5C tests an already-enrolled host; it does not enroll.'
    Complete-Run
}

$statusBefore = (& $agentExe status 2>&1) -join ' '
if ($statusBefore -notmatch $IdentityPattern) {
    Add-Result 'enrollment state' 'unusable'
    Add-Failure ('The agent does not report an enrolled host: {0}' -f $statusBefore.Trim())
    Complete-Run
}
$deviceBefore = $Matches['device']
if ($deviceBefore -ne $ExpectedDeviceId) {
    Add-Result 'enrollment state' ('unexpected device {0}' -f $deviceBefore)
    Add-Failure ('This host reports device {0}; Gate 5C expects {1}. Nothing was run.' -f
        $deviceBefore, $ExpectedDeviceId)
    Complete-Run
}
Add-Result 'enrollment state' ('enrolled as the expected device {0}' -f $deviceBefore)

$credentialBefore = Get-CredentialFingerprint
Add-Result 'credential before' ('sha256 {0}, {1} bytes, written {2}' -f
    $credentialBefore.Digest.Substring(0, 16), $credentialBefore.Length, (Format-Utc $credentialBefore.Written))
$filesBefore = @(Get-ChildItem -LiteralPath $CredentialStore -File | Select-Object -ExpandProperty Name | Sort-Object)
Add-Result 'credential store before' ($filesBefore -join ', ')
$sequenceBefore = Get-StoredSequence
Add-Result 'stored sequence before' $(if ($null -eq $sequenceBefore) { 'none (this host has never beaten)' } else { "$sequenceBefore" })

# ---------------------------------------------------------------------------------------------------------
# 4. Phase A: the first heartbeats. Two, so the interval between them is observed rather than assumed.
# ---------------------------------------------------------------------------------------------------------

Write-Host 'Phase A: first heartbeats (up to 3 minutes) ...'
$phaseA = Invoke-Phase -Phase 'phase-a-first' -Label 'first heartbeats' -Beats 2 -TimeoutSeconds 200
Add-Result 'phase A window' ('{0} to {1}' -f (Format-Utc $phaseA.StartedAt), (Format-Utc $phaseA.StoppedAt))
Add-Result 'phase A accepted beats' "$($phaseA.Accepted)"
if ($phaseA.Accepted -lt 2) {
    Add-Failure ('Phase A saw {0} accepted heartbeat(s); two were expected. See {1} on this host.' -f
        $phaseA.Accepted, $phaseA.Log)
}
Add-Result 'phase A platform status' $(if ($phaseA.Statuses) { $phaseA.Statuses } else { 'none reported' })
Add-Result 'phase A advisory interval' $(if ($phaseA.Intervals) { "$($phaseA.Intervals)s" } else { 'none reported' })
Add-Result 'phase A observed cadence' $(if ($phaseA.Cadence) { $phaseA.Cadence } else { 'not measurable' })
Add-Result 'phase A sequence' $(if ($null -eq $phaseA.Sequence) { 'no counter written' } else { "$($phaseA.Sequence)" })
Add-Result 'phase A process' $(if ($phaseA.Alive) { 'still healthy when stopped' } else { 'exited on its own' })
if (-not $phaseA.Alive) {
    Add-Failure 'The agent process exited on its own during phase A; it is expected to keep running.'
}

# ---------------------------------------------------------------------------------------------------------
# 5. Phase B: restart. Same identity, same credential, counter moves forward, nothing enrolls.
# ---------------------------------------------------------------------------------------------------------

Write-Host 'Phase B: restart with the existing credential (up to 2 minutes) ...'
$phaseB = Invoke-Phase -Phase 'phase-b-restart' -Label 'restart' -Beats 1 -TimeoutSeconds 120
Add-Result 'phase B window' ('{0} to {1}' -f (Format-Utc $phaseB.StartedAt), (Format-Utc $phaseB.StoppedAt))
Add-Result 'phase B accepted beats' "$($phaseB.Accepted)"
if ($phaseB.Accepted -lt 1) {
    Add-Failure ('Phase B saw no accepted heartbeat after the restart. See {0} on this host.' -f $phaseB.Log)
}
Add-Result 'phase B device' $(if ($phaseB.Device) { $phaseB.Device } else { 'not reported' })
if ($phaseB.Device -and $phaseB.Device -ne $ExpectedDeviceId) {
    Add-Failure ('After the restart the agent reported device {0}, not {1}.' -f $phaseB.Device, $ExpectedDeviceId)
}
Add-Result 'phase B sequence' $(if ($null -eq $phaseB.Sequence) { 'no counter written' } else { "$($phaseB.Sequence)" })
if ($null -ne $phaseA.Sequence -and $null -ne $phaseB.Sequence -and $phaseB.Sequence -le $phaseA.Sequence) {
    Add-Failure ('The sequence counter did not advance across the restart: {0} then {1}.' -f
        $phaseA.Sequence, $phaseB.Sequence)
}

# ---------------------------------------------------------------------------------------------------------
# 6. Phase C: silence, for longer than the platform's threshold plus one sweep. This side records the window;
#    the platform decides what it means.
# ---------------------------------------------------------------------------------------------------------

$silenceFrom = Get-Utc
Write-Host ("Phase C: staying silent for {0} seconds so the platform can mark this device offline ..." -f $OfflineWaitSeconds)
$remaining = $OfflineWaitSeconds
while ($remaining -gt 0) {
    $step = [Math]::Min(30, $remaining)
    Start-Sleep -Seconds $step
    $remaining -= $step
    Write-Host ("  {0}s remaining" -f $remaining)
}
$silenceTo = Get-Utc
Add-Result 'phase C silent window' ('{0} to {1} ({2}s, no heartbeat sent)' -f
    (Format-Utc $silenceFrom), (Format-Utc $silenceTo), $OfflineWaitSeconds)

$runningDuringSilence = @(Get-Process -Name 'eeop-agent' -ErrorAction SilentlyContinue)
Add-Result 'phase C agent processes' ('{0} running' -f $runningDuringSilence.Count)
if ($runningDuringSilence.Count -gt 0) {
    Add-Failure 'An eeop-agent process was running during the silent window, so the silence was not real.'
}

# ---------------------------------------------------------------------------------------------------------
# 7. Phase D: recovery. The same host, the same credential, beating again.
# ---------------------------------------------------------------------------------------------------------

Write-Host 'Phase D: recovery (up to 3 minutes) ...'
$phaseD = Invoke-Phase -Phase 'phase-d-recovery' -Label 'recovery' -Beats 2 -TimeoutSeconds 200
Add-Result 'phase D window' ('{0} to {1}' -f (Format-Utc $phaseD.StartedAt), (Format-Utc $phaseD.StoppedAt))
Add-Result 'phase D accepted beats' "$($phaseD.Accepted)"
if ($phaseD.Accepted -lt 1) {
    Add-Failure ('Phase D saw no accepted heartbeat after the silent window. See {0} on this host.' -f $phaseD.Log)
}
Add-Result 'phase D platform status' $(if ($phaseD.Statuses) { $phaseD.Statuses } else { 'none reported' })
Add-Result 'phase D observed cadence' $(if ($phaseD.Cadence) { $phaseD.Cadence } else { 'not measurable' })
Add-Result 'phase D sequence' $(if ($null -eq $phaseD.Sequence) { 'no counter written' } else { "$($phaseD.Sequence)" })
if ($null -ne $phaseB.Sequence -and $null -ne $phaseD.Sequence -and $phaseD.Sequence -le $phaseB.Sequence) {
    Add-Failure ('The sequence counter did not advance across the silent window: {0} then {1}.' -f
        $phaseB.Sequence, $phaseD.Sequence)
}

# ---------------------------------------------------------------------------------------------------------
# 8. The invariants that hold across every phase: one identity, one credential, no enrollment, no secret in
#    the capture.
# ---------------------------------------------------------------------------------------------------------

$credentialAfter = Get-CredentialFingerprint
Add-Result 'credential after' ('sha256 {0}, {1} bytes, written {2}' -f
    $credentialAfter.Digest.Substring(0, 16), $credentialAfter.Length, (Format-Utc $credentialAfter.Written))
if ($credentialAfter.Digest -ne $credentialBefore.Digest -or
    $credentialAfter.Written -ne $credentialBefore.Written) {
    Add-Failure ('The stored credential changed during the test, which means something re-enrolled this host.')
}
else {
    Add-Result 'credential unchanged' 'yes (same digest and write time throughout)'
}

$filesAfter = @(Get-ChildItem -LiteralPath $CredentialStore -File | Select-Object -ExpandProperty Name | Sort-Object)
Add-Result 'credential store after' ($filesAfter -join ', ')
$added = @($filesAfter | Where-Object { $filesBefore -notcontains $_ })
if ($added.Count -gt 0 -and @($added | Where-Object { $_ -ne 'heartbeat.json' }).Count -gt 0) {
    Add-Failure ('Unexpected files appeared in the credential store: {0}' -f ($added -join ', '))
}

$logs = @(Get-ChildItem -LiteralPath $LogRoot -File -Filter '*.log' | Select-Object -ExpandProperty FullName)
$enrolmentMentions = @(Select-String -Path $logs -Pattern 'enrollment token|Enrolled device|no device credential' -ErrorAction SilentlyContinue)
if ($enrolmentMentions.Count -gt 0) {
    Add-Result 'reenrollment' 'the agent log mentions enrollment'
    Add-Failure ('The agent log mentions enrollment {0} time(s); no phase should have attempted it.' -f
        $enrolmentMentions.Count)
}
else {
    Add-Result 'reenrollment' 'none (no enrollment attempt in any phase)'
}

$refusals = @(Select-String -Path $logs -Pattern 'not accepted|gave up after' -ErrorAction SilentlyContinue)
Add-Result 'refused or abandoned cycles' "$($refusals.Count)"

$markerHits = @(Select-String -Path $logs -Pattern ($SensitiveMarkers -join '|') -ErrorAction SilentlyContinue)
if ($markerHits.Count -gt 0) {
    Add-Result 'log scan' 'sensitive marker found'
    Add-Failure ('The captured agent log matched a sensitive marker {0} time(s); do not share the capture.' -f
        $markerHits.Count)
}
else {
    Add-Result 'log scan' 'clean (no key, signature, header or token marker in the capture)'
}

$statusAfter = (& $agentExe status 2>&1) -join ' '
if ($statusAfter -match $IdentityPattern -and $Matches['device'] -eq $ExpectedDeviceId) {
    Add-Result 'identity after test' ('enrolled as device {0}' -f $ExpectedDeviceId)
}
else {
    Add-Result 'identity after test' 'not reported'
    Add-Failure ('After the test the agent does not report the expected device: {0}' -f $statusAfter.Trim())
}

$leftRunning = @(Get-Process -Name 'eeop-agent' -ErrorAction SilentlyContinue)
Add-Result 'agent running at exit' $(if ($leftRunning.Count -eq 0) { 'no (host left as found)' } else { 'yes' })
if ($leftRunning.Count -gt 0) {
    Add-Failure 'An eeop-agent process is still running; stop it before reporting the result.'
}

Add-Result 'captured agent logs' $LogRoot

Complete-Run
