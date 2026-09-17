# JOCKY installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo    = "vmmuthu31/jocky"
$BinName = "jocky-compile.exe"
$InstallDir = if ($env:JOCKY_INSTALL_DIR) { $env:JOCKY_INSTALL_DIR } else {
    Join-Path $env:USERPROFILE ".jocky\bin"
}

# Only x86_64 Windows for now
$Artifact = "jocky-windows-x86_64.exe"

# Get latest release
$Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
$Tag = $Release.tag_name

if (-not $Tag) {
    Write-Error "Could not fetch latest release. Check https://github.com/$Repo/releases"
    exit 1
}

$Url = "https://github.com/$Repo/releases/download/$Tag/$Artifact"

Write-Host "Installing JOCKY $Tag..."
Write-Host "From: $Url"
Write-Host "To:   $InstallDir\$BinName"

# Create install dir
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

$Dest = Join-Path $InstallDir $BinName
Invoke-WebRequest -Uri $Url -OutFile $Dest

# Add to PATH for current user if not already there
$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($CurrentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$InstallDir", "User")
    Write-Host "Added $InstallDir to your PATH (restart terminal to take effect)"
}

Write-Host ""
Write-Host "JOCKY installed -> $Dest"
Write-Host ""
Write-Host "Quick start:"
Write-Host "  jocky-compile --help"
Write-Host "  jocky-compile new triage --output my_scan.jocky"
Write-Host "  jocky-compile compile --input my_scan.jocky --output out.ll --target windows"
