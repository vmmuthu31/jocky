# JOCKY Windows installer — downloads the latest release binary.
# Usage (PowerShell): irm https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo    = "vmmuthu31/jocky"
$Binary  = "jocky-compile.exe"
$InstDir = "$env:USERPROFILE\.jocky\bin"
$Asset   = "jocky-windows-x86_64.exe"

# Fetch latest release tag
Write-Host "Checking latest JOCKY release..."
$Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
$Tag     = $Release.tag_name

if (-not $Tag) {
    Write-Error "Could not determine latest release. Check https://github.com/$Repo/releases"
    exit 1
}

$Url = "https://github.com/$Repo/releases/download/$Tag/$Asset"

# Create install directory
New-Item -ItemType Directory -Force -Path $InstDir | Out-Null

$Dest = Join-Path $InstDir $Binary

Write-Host "Downloading JOCKY $Tag..."
Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing

# Add to user PATH if not already present
$UserPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstDir*") {
    [System.Environment]::SetEnvironmentVariable(
        "Path",
        "$UserPath;$InstDir",
        "User"
    )
    Write-Host "Added $InstDir to your user PATH."
    Write-Host "Restart your terminal for the PATH change to take effect."
}

Write-Host ""
Write-Host "Installed to: $Dest"
Write-Host ""
Write-Host "Verify with:"
Write-Host "  jocky-compile --help"
Write-Host ""
Write-Host "Quick start (development mode):"
Write-Host "  `$env:JOCKY_ALLOW_DEV_KEY=`"1`"; jocky-compile compile --input scan.jocky --output scan.ll --target windows"
