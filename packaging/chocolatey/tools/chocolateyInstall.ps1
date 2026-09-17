$ErrorActionPreference = 'Stop'

$packageName = 'jocky'
$version     = '1.0.0'
$url64       = "https://github.com/vmmuthu31/jocky/releases/download/v${version}/jocky-windows-x86_64.exe"
$installDir  = Join-Path $env:ChocolateyBinRoot 'jocky'

New-Item -ItemType Directory -Force -Path $installDir | Out-Null

$dest = Join-Path $installDir 'jocky-compile.exe'
Get-ChocolateyWebFile $packageName $dest $url64

Install-ChocolateyPath $installDir 'Machine'

Write-Host ""
Write-Host "JOCKY installed. Run: jocky-compile --help"
