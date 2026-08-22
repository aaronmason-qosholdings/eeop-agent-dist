<#
.SYNOPSIS
    Prepares one dedicated internal Windows Server host for the Sprint 3 Gate 4 enrollment, and stops before it.

.DESCRIPTION
    Installs the approved self-contained win-x64 agent, verifies it against published hashes, proves the host
    can reach the Development ingestion API, confirms the host holds no device identity and no enrollment
    token, runs 'configure', and records the result.

    The build it installs is the canonical one, which carries both the enrollment path Gate 4 proves and the
    heartbeat worker Gate 5 proves, so a host is prepared once and needs no second agent installed later.

    The canonical validation host is Windows Server 2025 (a standalone server for the first validation), and
    this package is pinned to it: the host name, the processor architecture, the operating system and the host
    clock are all asserted before a byte is downloaded or extracted, so a command pasted into the wrong window
    stops instead of installing an agent there. The agent is self-contained, so no runtime is installed, and
    no build number is matched, because servicing changes it.

    It does not enroll, does not provision or read a token, does not install a service and does not start
    heartbeat work. It requires no .NET SDK, no .NET runtime and no Azure CLI.

    Nothing it prints or writes can contain a token, a private key, an Authorization header or signing
    material: the only agent state it reads is the configuration file, which holds the platform address alone.

.PARAMETER AgentPackage
    Path to an already-downloaded eeop-agent-win-x64.zip. By default the script downloads the pinned public
    release asset itself. Either way the package is verified against the hash pinned below before anything is
    extracted, so a supplied file is not trusted more than a downloaded one.

.PARAMETER PlatformUri
    The platform the host is configured against. Defaults to the Development ingestion API.

.PARAMETER ExpectedHostname
    The one host this package prepares. The default is the canonical validation server, and a mismatch is a
    hard stop rather than a warning.

.PARAMETER ClockToleranceSeconds
    How far the host clock may sit from the platform's own clock. Deliberately tighter than the +/-300s the
    device authentication model allows, so a drifting clock is found here rather than after a single-use
    enrollment token has already been spent on it.

.PARAMETER LoadFunctionsOnly
    Dot-source the prerequisite decisions without preparing anything. Only the tests use it.

.EXAMPLE
    PS> .\EEOP-Gate4-Prepare.ps1
#>

[CmdletBinding()]
param(
    [string] $AgentPackage,
    [string] $PlatformUri = 'https://eeop-dev-ingestion-api.azurewebsites.net/',
    [string] $ExpectedHostname = 'EEOP-SRV2025-01',
    [int] $ClockToleranceSeconds = 120,
    [switch] $LoadFunctionsOnly
)

# ---------------------------------------------------------------------------------------------------------
# The prerequisite decisions, kept free of the host and the network so they can be tested anywhere. Each one
# returns the sanitized text for the results file alongside its verdict, so a caller cannot record a pass and
# describe a failure: both come from the same call.
# ---------------------------------------------------------------------------------------------------------

function Test-EeopHostname {
    param([string] $Actual, [string] $Expected)

    # Case-insensitive, because Windows host names are, and trimmed, because a pasted name can carry spaces.
    $ok = $Actual.Trim() -ieq $Expected.Trim()
    $message = $null
    if (-not $ok) {
        $message = "This package prepares $Expected only, and this host is $Actual. Nothing was downloaded, " +
            'extracted or configured. Run it on the canonical validation server, or pass -ExpectedHostname if ' +
            'the canonical host has been renamed.'
    }
    return [pscustomobject]@{ Ok = $ok; Value = $Actual; Message = $message }
}

function Test-EeopArchitecture {
    param([string] $Architecture)

    # The agent artifact is win-x64 and self-contained: on x86 or ARM64 it would not run at all, and there is
    # no sense in discovering that after it is installed.
    $normalized = if ($Architecture) { $Architecture.Trim() } else { '' }
    $ok = $normalized -ieq 'AMD64' -or $normalized -ieq 'x64'
    $message = $null
    if (-not $ok) {
        $message = "The approved agent is win-x64 and this host reports '$normalized'. x86, ARM64 and unknown " +
            'architectures are refused. Nothing was downloaded, extracted or configured.'
    }
    $value = if ($normalized) { $normalized } else { 'unknown' }
    return [pscustomobject]@{ Ok = $ok; Value = $value; Message = $message }
}

function Test-EeopWindowsServer2025 {
    param([string] $Caption, [int] $ProductType)

    # Product type separates a server from a workstation without reading a build number, and the caption names
    # the release. Servicing moves the build, so the build is recorded and never matched.
    $isServer = $ProductType -eq 2 -or $ProductType -eq 3
    $is2025 = $Caption -match '(?i)windows\s+server\s+2025'
    $ok = $isServer -and $is2025
    $message = $null
    if (-not $ok) {
        $message = "The canonical validation host is Windows Server 2025, and this host reports '$Caption' " +
            "(product type $ProductType). Nothing was downloaded, extracted or configured."
    }
    return [pscustomobject]@{ Ok = $ok; Value = $Caption; Message = $message }
}

function Get-EeopClockDifference {
    param([datetime] $PlatformUtc, [datetime] $HostUtc)

    # Positive means the host is ahead of the platform. Rounded to a tenth, which is more resolution than the
    # Date header's whole seconds can justify anyway.
    return [math]::Round(($HostUtc - $PlatformUtc).TotalSeconds, 1)
}

function Test-EeopClockDifference {
    param([double] $DifferenceSeconds, [int] $ToleranceSeconds)

    $ok = [math]::Abs($DifferenceSeconds) -le $ToleranceSeconds
    $message = $null
    if (-not $ok) {
        $message = ('The host clock differs from the platform by {0}s, beyond the +/-{1}s this stage allows. ' -f
            $DifferenceSeconds, $ToleranceSeconds) +
            'Windows Time synchronization must be corrected before enrollment: a signed request outside the ' +
            'platform tolerance is refused, and the enrollment token is single use, so it would be spent on a ' +
            'failure. Nothing was downloaded, extracted or configured, and this script changed neither the ' +
            'clock nor the time service.'
    }
    $value = '{0}s (tolerance +/-{1}s)' -f $DifferenceSeconds, $ToleranceSeconds
    return [pscustomobject]@{ Ok = $ok; Value = $value; Message = $message }
}

if ($LoadFunctionsOnly) { return }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Published with the artifact. A mismatch is a hard stop: an unverified agent on a host that is about to hold
# a device private key is not a thing to shrug at.
# The canonical build is a superset of what any one gate needs, so preparing a host with it means the host
# that enrolls is the host that heartbeats, verified against one set of hashes rather than two.
$ExpectedPackageHash = '82c4a3354fda759a454c266091df1b4cf77f98f4d10481f1b8936b7754b80eac'
$ExpectedBinaryHashes = [ordered]@{
    'eeop-agent.exe'     = '8f5f61451dc30302f42f64dc95ae8f283e0b9ef9774b277e6d999bce2a721232'
    'eeop-agent.dll'     = 'b0e37d337deb61bdcffa7b8f8a84f496a78713bf3c8e2085331f1a41bec30924'
    'EEOP.Contracts.dll' = '908207b8c5076dde21618ca851e037ad436b98c2cc71d6736387444d58e2cdb9'
}
$AgentCommit = 'ff7a8cde734fa9e158de8cc9200d618c39b3d817'
$PackageName = 'eeop-agent-win-x64.zip'
$PackageUrl = 'https://github.com/QOS-Holdings/eeop-agent-dist/releases/download/gateb1-ff7a8cd/eeop-agent-win-x64.zip'

$Root = 'C:\ProgramData\EEOP'
$WorkRoot = Join-Path $Root 'Gate4'
$InstallRoot = Join-Path $WorkRoot 'agent'
$ResultsPath = Join-Path $WorkRoot 'gate4-preparation-results.txt'
$CredentialStore = Join-Path $Root 'Agent'

# A short reference for this run, so a result can be cited without quoting the whole file.
$RunId = 'GATE4-{0:yyyyMMdd-HHmmss}Z-{1}' -f (Get-Date).ToUniversalTime(), $env:COMPUTERNAME
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

# Only the exception's own message, which the agent and .NET write without secret values in them. No stack
# trace, no command line, no environment dump.
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
    $lines.Add('EEOP Gate 4 - Windows host preparation') | Out-Null
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
    $lines.Add('This file is safe to share: it holds no token, private key, signature or credential.') | Out-Null

    New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
    Set-Content -Path $ResultsPath -Value $lines -Encoding UTF8
}

function Complete-Run {
    $passed = $script:failures.Count -eq 0
    Write-ResultFile -Passed $passed
    Write-Host ''
    if ($passed) {
        Write-Host 'EEOP Gate 4 preparation PASSED'
    }
    else {
        Write-Host 'EEOP Gate 4 preparation FAILED'
    }
    Write-Host "Reference: $script:RunId"
    Write-Host 'Results:'
    Write-Host $ResultsPath
    Write-Host ''
    # The file is sanitized by construction, so the simplest way to hand it back is the whole file.
    Write-Host 'To send the results back, run either of:'
    Write-Host "  Get-Content $ResultsPath"
    Write-Host "  Get-Content $ResultsPath | Set-Clipboard"
    exit $(if ($passed) { 0 } else { 1 })
}

function Resolve-AgentPackage {
    if ($AgentPackage) {
        if ($AgentPackage -match '^https://') {
            $supplied = Join-Path $WorkRoot $PackageName
            Invoke-WebRequest -Uri $AgentPackage -OutFile $supplied -UseBasicParsing -TimeoutSec 900
            return $supplied
        }
        return $AgentPackage
    }

    # The pinned public release asset. A release tag's asset cannot be replaced in place, and the hash is
    # checked before a single byte is extracted, so the download is the convenience and the hash is the
    # control: a substituted artifact stops the run rather than reaching the host.
    $destination = Join-Path $WorkRoot $PackageName
    Write-Host 'downloading the approved agent package'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $PackageUrl -OutFile $destination -UseBasicParsing -TimeoutSec 900
    return $destination
}

# ---------------------------------------------------------------------------------------------------------
# 1. Host identity, and every prerequisite that can refuse the run. All of it happens before the package is
#    downloaded or extracted, so a wrong host ends with a results file and no agent on disk.
# ---------------------------------------------------------------------------------------------------------

Add-Result 'reference' $RunId
Add-Result 'expected agent commit' $AgentCommit

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Result 'elevated' 'no'
    Add-Failure 'This script must run from an elevated PowerShell; the credential store directory cannot otherwise be created with its restricted ACL.'
    Complete-Run
}
Add-Result 'elevated' 'yes'

$hostname = Test-EeopHostname -Actual $env:COMPUTERNAME -Expected $ExpectedHostname
Add-Result 'hostname' ('{0} (expected {1})' -f $hostname.Value, $ExpectedHostname)
if (-not $hostname.Ok) {
    Add-Failure $hostname.Message
    Complete-Run
}

# PROCESSOR_ARCHITEW6432 is set only inside a 32-bit process on 64-bit Windows, where PROCESSOR_ARCHITECTURE
# reports x86 and would refuse a host that is in fact fine.
$architecture = Test-EeopArchitecture -Architecture $(
    if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE })
Add-Result 'architecture' $architecture.Value
if (-not $architecture.Ok) {
    Add-Failure $architecture.Message
    Complete-Run
}

try {
    $os = Get-CimInstance Win32_OperatingSystem
}
catch {
    Add-Result 'windows' ('unavailable: {0}' -f (Get-SafeError $_))
    Add-Failure ('The operating system could not be read, so this host cannot be confirmed as the canonical ' +
        'validation server: {0}' -f (Get-SafeError $_))
    Complete-Run
}
Add-Result 'windows' ('{0} (version {1}, build {2}, product type {3})' -f
    $os.Caption, $os.Version, $os.BuildNumber, $os.ProductType)
$operatingSystem = Test-EeopWindowsServer2025 -Caption $os.Caption -ProductType $os.ProductType
if (-not $operatingSystem.Ok) {
    Add-Failure $operatingSystem.Message
    Complete-Run
}

# The platform's own clock, read from the response header of a probe that has to succeed anyway. Nothing here
# adjusts the host clock or the time service; a drifting host is reported, not repaired.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$clockProbe = "$($PlatformUri.TrimEnd('/'))/health/live"
try {
    $probe = Invoke-WebRequest -Uri $clockProbe -UseBasicParsing -TimeoutSec 30
    $hostUtc = (Get-Date).ToUniversalTime()
    $platformUtc = [datetime]::Parse(
        [string]($probe.Headers['Date']),
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
}
catch {
    Add-Result 'clock difference' 'unavailable'
    Add-Failure ('{0} could not be read, so the host clock could not be compared with the platform: {1}' -f
        $clockProbe, (Get-SafeError $_))
    Complete-Run
}

$clock = Test-EeopClockDifference `
    -DifferenceSeconds (Get-EeopClockDifference -PlatformUtc $platformUtc -HostUtc $hostUtc) `
    -ToleranceSeconds $ClockToleranceSeconds
Add-Result 'clock difference' $clock.Value
if (-not $clock.Ok) {
    Add-Failure $clock.Message
    Complete-Run
}

try {
    New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    Add-Result 'working directory' $WorkRoot
}
catch {
    Add-Result 'working directory' 'failed'
    Add-Failure ('The working directories could not be created: {0}' -f (Get-SafeError $_))
    Complete-Run
}

# ---------------------------------------------------------------------------------------------------------
# 2. The package, verified before anything is extracted.
# ---------------------------------------------------------------------------------------------------------

try {
    $package = Resolve-AgentPackage
    Add-Result 'agent package' $package
}
catch {
    Add-Result 'agent package' 'not found'
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
    Add-Result 'install' 'failed'
    Add-Failure ('The package could not be extracted: {0}' -f (Get-SafeError $_))
    Complete-Run
}

$agentExe = Join-Path $InstallRoot 'eeop-agent.exe'
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
    Add-Failure ('The installed binaries do not match the approved artifact: {0}' -f ($mismatched -join '; '))
    Complete-Run
}
Add-Result 'binaries verified' ('yes ({0})' -f ($ExpectedBinaryHashes.Keys -join ', '))
Add-Result 'install directory' $InstallRoot

try {
    # The apphost carries no version of ours, so the build is read from the managed assembly.
    $version = (Get-Item (Join-Path $InstallRoot 'eeop-agent.dll')).VersionInfo
    Add-Result 'agent build' ('{0} (file {1}, product {2})' -f 'eeop-agent.dll', $version.FileVersion, $version.ProductVersion)
}
catch {
    Add-Result 'agent build' ('unavailable: {0}' -f (Get-SafeError $_))
}

# ---------------------------------------------------------------------------------------------------------
# 3. Reachability. Both probes, because a platform that answers /health/live but not /health/ready is a
#    platform that cannot serve an enrollment.
# ---------------------------------------------------------------------------------------------------------

$base = $PlatformUri.TrimEnd('/')
foreach ($probe in @('live', 'ready')) {
    $label = "$probe health"
    $uri = "$base/health/$probe"
    try {
        $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 30
        Add-Result $label ('HTTP {0} from {1}' -f [int]$response.StatusCode, $uri)
        if ([int]$response.StatusCode -ne 200) {
            Add-Failure ('{0} returned HTTP {1}; 200 is required.' -f $uri, [int]$response.StatusCode)
        }
    }
    catch {
        Add-Result $label ('unreachable: {0}' -f $uri)
        Add-Failure ('{0} could not be reached: {1}' -f $uri, (Get-SafeError $_))
    }
}

# ---------------------------------------------------------------------------------------------------------
# 4. The host must be clean: no identity to overwrite, and no token anywhere near this session.
# ---------------------------------------------------------------------------------------------------------

$credentialFile = Join-Path $CredentialStore 'credential.bin'
if (Test-Path -LiteralPath $credentialFile) {
    Add-Result 'existing identity' 'yes'
    Add-Failure ("$credentialFile already exists, so this host may already be enrolled. " +
        'Preparation stops rather than disturbing an existing device identity.')
    Complete-Run
}
Add-Result 'existing identity' 'no'

if ($env:EEOP_AGENT_ENROLLMENT_TOKEN) {
    Add-Result 'enrollment token present' 'yes'
    Add-Failure ('EEOP_AGENT_ENROLLMENT_TOKEN is set in this session. Host preparation must run without a ' +
        'token; clear it with Remove-Item Env:\EEOP_AGENT_ENROLLMENT_TOKEN and run this again.')
    Complete-Run
}
Add-Result 'enrollment token present' 'no'

# ---------------------------------------------------------------------------------------------------------
# 5. Configure, then read back the state the service itself would report.
# ---------------------------------------------------------------------------------------------------------

$env:EEOP_AGENT_PLATFORM_URI = $PlatformUri
try {
    $configureOutput = & $agentExe configure 2>&1
    $configureExit = $LASTEXITCODE
}
catch {
    Add-Result 'configuration' 'failed'
    Add-Failure ('configure could not be run: {0}' -f (Get-SafeError $_))
    Complete-Run
}
finally {
    Remove-Item Env:\EEOP_AGENT_PLATFORM_URI -ErrorAction SilentlyContinue
}

if ($configureExit -ne 0) {
    Add-Result 'configuration' ('failed (exit {0})' -f $configureExit)
    Add-Failure ('configure exited {0}: {1}' -f $configureExit, (($configureOutput -join ' ').Trim()))
    Complete-Run
}
Add-Result 'configuration' ('written for {0}' -f $PlatformUri)

try {
    Add-Result 'credential store acl' (Get-Acl -Path $CredentialStore).Sddl
}
catch {
    Add-Result 'credential store acl' ('unavailable: {0}' -f (Get-SafeError $_))
}

# 'status' exits 1 while the host holds no credential, which is the expected state here: the exit code
# reports enrollment, and this step is deliberately before enrollment.
$statusOutput = (& $agentExe status 2>&1) -join ' '
$statusExit = $LASTEXITCODE
$configured = $statusOutput -match 'configuration loaded from'
$enrolled = $statusOutput -match 'enrolled as device'
$unenrolled = $statusOutput -match 'holds no device credential'

if ($enrolled) {
    Add-Result 'enrollment state' 'enrolled - unexpected at this stage'
    Add-Failure 'The agent reports a device identity, but preparation must end unenrolled. Nothing was enrolled by this script.'
}
elseif ($unenrolled -and $configured -and $statusExit -eq 1) {
    Add-Result 'enrollment state' 'configured, not enrolled (expected)'
}
else {
    Add-Result 'enrollment state' ('indeterminate (exit {0})' -f $statusExit)
    Add-Failure ('status did not report a configured, unenrolled host: {0}' -f $statusOutput.Trim())
}
Add-Result 'agent status' $statusOutput.Trim()

Complete-Run
