<#
.SYNOPSIS
    Prepares one dedicated internal Windows test host for the Sprint 3 Gate 4 enrollment, and stops before it.

.DESCRIPTION
    Installs the approved self-contained win-x64 agent, verifies it against published hashes, proves the host
    can reach the Development ingestion API, confirms the host holds no device identity and no enrollment
    token, runs 'configure', and records the result.

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

.EXAMPLE
    PS> .\EEOP-Gate4-Prepare.ps1
#>

[CmdletBinding()]
param(
    [string] $AgentPackage,
    [string] $PlatformUri = 'https://eeop-dev-ingestion-api.azurewebsites.net/'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Published with the artifact. A mismatch is a hard stop: an unverified agent on a host that is about to hold
# a device private key is not a thing to shrug at.
$ExpectedPackageHash = '02878021553aa5d47b405af88256afb86b01bff007f6ca07fe184b460ccb835e'
$ExpectedBinaryHashes = [ordered]@{
    'eeop-agent.exe'     = '234a7feb15bd4ce1d0a5999eed53f5e41864db6612266f63f56c45edb9d4802d'
    'eeop-agent.dll'     = '97709c2b2862c152c9cdb475bd672c23b00530d25b4d0700ec062c9d361774e4'
    'EEOP.Contracts.dll' = '3ee7de7edaedbc4e7d0610d5361e6486b2ef1980c06a95536dc96b6339871d1a'
}
$AgentCommit = 'fcea97b0e73219bc0134d0f76e9d127d2b16184c'
$PackageName = 'eeop-agent-win-x64.zip'
$PackageUrl = 'https://github.com/aaronmason-qosholdings/eeop-agent-dist/releases/download/gate4-fcea97b/eeop-agent-win-x64.zip'

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
    $lines.Add('EEOP Gate 4 — Windows host preparation') | Out-Null
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
# 1. Host identity, and the working directories.
# ---------------------------------------------------------------------------------------------------------

Add-Result 'reference' $RunId
Add-Result 'hostname' $env:COMPUTERNAME
try {
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Result 'windows' ('{0} ({1}, {2})' -f $os.Caption, $os.Version, $env:PROCESSOR_ARCHITECTURE)
}
catch {
    Add-Result 'windows' ('unavailable: {0}' -f (Get-SafeError $_))
}
Add-Result 'expected agent commit' $AgentCommit

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Result 'elevated' 'no'
    Add-Failure 'This script must run from an elevated PowerShell; the credential store directory cannot otherwise be created with its restricted ACL.'
    Complete-Run
}
Add-Result 'elevated' 'yes'

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
    Add-Result 'enrollment state' 'enrolled — unexpected at this stage'
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
