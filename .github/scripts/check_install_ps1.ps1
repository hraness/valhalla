# Install a locally built Windows zip through site/install.ps1, the way
# `irm https://vhalla.com/install.ps1 | iex` runs it, then again under
# Windows PowerShell 5.1 to replace the installed copy.
#
#   pwsh .github/scripts/check_install_ps1.ps1 -Exe PATH\vhalla.exe -Version vX.Y.Z
#
# Stages valhalla-<version>-x86_64-pc-windows-msvc.zip + .sha256 exactly as
# release.yml packages them and serves them from 127.0.0.1.
param(
  [Parameter(Mandatory)] [string] $Exe,
  [Parameter(Mandatory)] [string] $Version,
  [string] $Zip
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$root = Join-Path ([IO.Path]::GetTempPath()) ('vhalla-install-check-' + [Guid]::NewGuid().ToString('N'))
$serve = Join-Path $root 'serve'
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force -Path $serve | Out-Null
$asset = "valhalla-$Version-x86_64-pc-windows-msvc.zip"
if ($Zip) {
  Copy-Item -LiteralPath $Zip -Destination (Join-Path $serve $asset)
} else {
  python -c "import sys, zipfile; z = zipfile.ZipFile(sys.argv[1], 'w', zipfile.ZIP_DEFLATED); z.write(sys.argv[2], 'vhalla.exe'); z.close()" (Join-Path $serve $asset) $Exe
  if ($LASTEXITCODE -ne 0) { throw 'could not stage the zip' }
}
$sum = (Get-FileHash -LiteralPath (Join-Path $serve $asset) -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $serve "$asset.sha256"), "$sum  $asset`n")

$port = 8765
$server = Start-Process python -ArgumentList '-m', 'http.server', "$port", '--bind', '127.0.0.1', '--directory', $serve -PassThru -WindowStyle Hidden
try {
  Start-Sleep -Seconds 2
  $env:VHALLA_VERSION = $Version
  $env:VHALLA_RELEASE_BASE_URL = "http://127.0.0.1:$port"
  $env:VHALLA_INSTALL_DIR = $bin
  $env:VHALLA_NO_MODIFY_PATH = '1'
  $installer = Join-Path $PSScriptRoot '..\..\site\install.ps1'

  Get-Content -Raw -LiteralPath $installer | Invoke-Expression
  $installed = Join-Path $bin 'vhalla.exe'
  $reported = (& $installed --version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $reported -notlike 'vhalla * features=*') { throw "installed vhalla reports '$reported'" }
  Write-Host "pwsh install ok: $reported"

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer
  if ($LASTEXITCODE -ne 0) { throw 'Windows PowerShell 5.1 reinstall failed' }
  if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash) {
    throw 'the installed vhalla.exe differs from the built one'
  }
  Write-Host 'Windows PowerShell 5.1 reinstall ok'

  # A tampered checksum must stop the install before anything is replaced.
  [IO.File]::WriteAllText((Join-Path $serve "$asset.sha256"), ('0' * 64) + "  $asset`n")
  $failed = $false
  try { Get-Content -Raw -LiteralPath $installer | Invoke-Expression } catch {
    $failed = "$_" -like '*checksum mismatch*'
  }
  if (-not $failed) { throw 'a checksum mismatch did not stop the install' }
  Write-Host 'checksum mismatch refused'
} finally {
  Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
