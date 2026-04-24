<#
.SYNOPSIS
    YggdraSIM installer for Windows x86_64.

.DESCRIPTION
    Only the "clean" flavor is published for Windows. The HIL bridge is
    Linux-only (it requires udev monitoring and osmo-remsim-client-st2)
    and cannot be installed on Windows.

    Two installation modes are supported:

      * release (default): download the published executable asset from
        the configured GitHub Releases page and drop it into a user-local
        bin directory.
      * source: create a virtualenv and perform an editable install of
        the YggdraSIM source tree.

.PARAMETER Flavor
    Flavor to install. Only "clean" is supported on Windows.

.PARAMETER Mode
    "release" (default) or "source".

.PARAMETER Version
    Release tag to download (default: "latest"). Ignored in source mode.

.PARAMETER InstallDir
    Target directory for the release binary
    (default: $env:LOCALAPPDATA\Programs\yggdrasim).

.PARAMETER RepoRoot
    Repository root for source mode (default: current directory).

.PARAMETER Venv
    Virtualenv path for source mode (default: <RepoRoot>\.venv).

.PARAMETER NoDeps
    Skip Chocolatey prerequisite installation.

.PARAMETER NoVenv
    Source mode: install into the current Python environment instead of
    creating a virtualenv.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install\install-windows.ps1 -Mode source
#>

[CmdletBinding()]
param(
    [ValidateSet('clean', 'full')]
    [string] $Flavor = 'clean',

    [ValidateSet('release', 'source')]
    [string] $Mode = 'release',

    [string] $Version = 'latest',

    [string] $InstallDir = "$env:LOCALAPPDATA\Programs\yggdrasim",

    [string] $RepoRoot = (Get-Location).Path,

    [string] $Venv = '',

    [switch] $NoDeps,

    [switch] $NoVenv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptName = 'install-windows.ps1'

function Write-YgInfo {
    param([string] $Message)
    Write-Host "[$script:ScriptName] $Message"
}

function Write-YgWarn {
    param([string] $Message)
    Write-Warning "[$script:ScriptName] $Message"
}

function Stop-YgError {
    param([string] $Message)
    throw "[$script:ScriptName] error: $Message"
}

if ($Flavor -eq 'full') {
    Stop-YgError "flavor 'full' is Linux-only; Windows only ships the 'clean' bundle"
}

$RepoOwner   = if ($env:YGGDRASIM_REPO) { $env:YGGDRASIM_REPO } else { 'hampushellsberg-dev/YggdraSIM' }
$ReleaseBase = "https://github.com/$RepoOwner/releases"

$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'arm64' }
    default { 'unknown' }
}

if ($Arch -eq 'unknown') {
    Stop-YgError "unsupported CPU architecture: $env:PROCESSOR_ARCHITECTURE"
}
if ($Arch -ne 'x86_64') {
    Write-YgWarn "no pre-built Windows release asset exists for '$Arch'; prefer -Mode source"
}

function Install-YgWindowsPrereqs {
    if ($NoDeps.IsPresent) {
        Write-YgInfo 'skipping Chocolatey prerequisite install (-NoDeps)'
        return
    }
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-YgWarn 'Chocolatey not installed; source builds may fail without swig/python'
        return
    }
    switch ($Mode) {
        'release' {
            # No hard prereqs for the release binary; PC/SC and gpg come from
            # the OS / Gpg4win respectively. Nudge the user without forcing.
            Write-YgInfo 'release mode: no Chocolatey packages required'
        }
        'source' {
            Write-YgInfo 'installing source prerequisites via Chocolatey (python, swig)'
            choco install -y python --version=3.11.9 | Out-Null
            choco install -y swig | Out-Null
        }
    }
}

function Resolve-YgReleaseUrl {
    param(
        [string] $VersionTag,
        [string] $AssetName
    )
    if ($VersionTag -eq 'latest') {
        return "$ReleaseBase/latest/download/$AssetName"
    }
    return "$ReleaseBase/download/$VersionTag/$AssetName"
}

function Install-YgFromRelease {
    $assetBase = "yggdrasim-windows-$Arch-$Flavor"
    $assetName = "$assetBase.exe"
    $url = Resolve-YgReleaseUrl -VersionTag $Version -AssetName $assetName
    $tempFile = New-TemporaryFile
    try {
        Write-YgInfo "downloading $url"
        Invoke-WebRequest -Uri $url -OutFile $tempFile -UseBasicParsing -MaximumRedirection 5

        if (-not (Test-Path -LiteralPath $InstallDir)) {
            New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        }

        $targetPath = Join-Path $InstallDir 'yggdrasim.exe'
        Copy-Item -LiteralPath $tempFile -Destination $targetPath -Force
        Write-YgInfo "installed $targetPath"

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not ($userPath -split ';' -contains $InstallDir)) {
            Write-YgWarn "'$InstallDir' is not on your user PATH; add it to keep 'yggdrasim' on $Env:PATH"
        }
        Write-YgInfo 'run: yggdrasim.exe --version'
    }
    finally {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Install-YgFromSource {
    if (-not (Test-Path -LiteralPath $RepoRoot)) {
        Stop-YgError "repository root not found: $RepoRoot"
    }
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        Stop-YgError 'python.exe not on PATH; install Python 3.10+ (e.g. choco install python)'
    }

    $venvPath = $Venv
    if (-not $NoVenv.IsPresent) {
        if (-not $venvPath) {
            $venvPath = Join-Path $RepoRoot '.venv'
        }
        if (-not (Test-Path -LiteralPath $venvPath)) {
            Write-YgInfo "creating virtualenv at $venvPath"
            & $pythonCmd.Source -m venv $venvPath
        }
        $activator = Join-Path $venvPath 'Scripts\Activate.ps1'
        if (-not (Test-Path -LiteralPath $activator)) {
            Stop-YgError "virtualenv activator missing: $activator"
        }
        . $activator
    }

    Push-Location -LiteralPath $RepoRoot
    try {
        python -m pip install --upgrade pip
        python -m pip install -e '.[saip]'
    }
    finally {
        Pop-Location
    }

    if ($venvPath) {
        Write-YgInfo "activate later with: . '$venvPath\Scripts\Activate.ps1'"
    }
}

Write-YgInfo "target host: windows/$Arch"
Write-YgInfo "flavor=$Flavor, mode=$Mode, version=$Version"

Install-YgWindowsPrereqs

switch ($Mode) {
    'release' { Install-YgFromRelease }
    'source'  { Install-YgFromSource }
}

Write-YgInfo 'done'
