# vhalla installer for Windows: download, verify (SHA-256), install, report.
# Usage (PowerShell):  irm https://vhalla.com/install.ps1 | iex
# Installs vhalla.exe for this user only; nothing runs as administrator.
# Options (environment): VHALLA_VERSION (one exact release, such as v0.2.10),
# VHALLA_INSTALL_DIR (default %LOCALAPPDATA%\Programs\vhalla\bin),
# VHALLA_NO_MODIFY_PATH=1 (leave the user PATH alone).
# On Windows, vhalla runs identity and the member side of private rooms. For
# every other command, install the Linux build inside WSL with install.sh.
# Source: https://github.com/hraness/valhalla
#
# Everything is inside one script block, so a partial download runs nothing.

& {
  Set-StrictMode -Version 3.0
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'

  $Version = 'v0.2.10'
  if ($env:VHALLA_VERSION) { $Version = $env:VHALLA_VERSION }
  if ($Version -cnotmatch '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw "vhalla install: VHALLA_VERSION must be an exact release such as v0.2.10 (got '$Version')"
  }
  $Base = "https://github.com/hraness/valhalla/releases/download/$Version"
  # The release workflow serves the archive it just built from loopback;
  # nothing else may replace the GitHub Release as the source.
  if ($env:VHALLA_RELEASE_BASE_URL) {
    if ($env:VHALLA_RELEASE_BASE_URL -cnotmatch '^http://127\.0\.0\.1:[0-9]{1,5}$') {
      throw 'vhalla install: VHALLA_RELEASE_BASE_URL may only name a loopback test server'
    }
    $Base = $env:VHALLA_RELEASE_BASE_URL
  }
  $Asset = "valhalla-$Version-x86_64-pc-windows-msvc.zip"
  $Guide = 'https://vhalla.com/docs/getting-started/'

  function Fail([string] $Message) {
    throw "vhalla install: $Message"
  }

  $arch = $env:PROCESSOR_ARCHITECTURE
  if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
  if ($arch -ne 'AMD64') {
    Fail "there is no prebuilt vhalla for Windows $arch. Prebuilt releases cover x86-64 Windows, Apple Silicon macOS, and x86-64 and ARM64 Linux. Build from source: $Guide"
  }

  if ($env:VHALLA_INSTALL_DIR) {
    $dir = $env:VHALLA_INSTALL_DIR
  } elseif ($env:LOCALAPPDATA) {
    $dir = Join-Path $env:LOCALAPPDATA 'Programs\vhalla\bin'
  } else {
    Fail 'LOCALAPPDATA is not set; set VHALLA_INSTALL_DIR to choose where vhalla goes'
  }
  if (-not [System.IO.Path]::IsPathRooted($dir)) { Fail 'VHALLA_INSTALL_DIR must be an absolute path' }
  $dir = [System.IO.Path]::GetFullPath($dir)

  # Windows PowerShell 5.1 may still offer only TLS 1.0 by default.
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("vhalla-install-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host "-> Downloading $Asset"
    $zip = Join-Path $tmp $Asset
    try {
      Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Asset" -OutFile $zip
      $recorded = (Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Asset.sha256").Content
    } catch {
      Fail "download failed for ${Asset} (does $Version have a Windows build?): $($_.Exception.Message)"
    }
    if ($recorded -is [byte[]]) { $recorded = [Text.Encoding]::ASCII.GetString($recorded) }

    Write-Host '-> Verifying SHA-256'
    $fields = "$recorded".Trim() -split '\s+'
    if ($fields.Count -ne 2 -or $fields[0] -cnotmatch '^[0-9a-f]{64}$' -or $fields[1] -cne $Asset) {
      Fail "the checksum file for $Asset is malformed"
    }
    $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $fields[0]) { Fail "checksum mismatch for $Asset (expected $($fields[0]), got $actual)" }

    # Admit exactly one entry, vhalla.exe, and copy its bytes to a path we
    # choose: archive paths never create files.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $candidate = Join-Path $tmp 'vhalla.exe'
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
    try {
      if ($archive.Entries.Count -ne 1 -or $archive.Entries[0].FullName -cne 'vhalla.exe') {
        Fail 'the archive must contain only vhalla.exe'
      }
      $source = $archive.Entries[0].Open()
      try {
        $target = [System.IO.File]::Open($candidate, 'CreateNew', 'Write', 'None')
        try { $source.CopyTo($target) } finally { $target.Dispose() }
      } finally { $source.Dispose() }
    } finally { $archive.Dispose() }

    & $candidate --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Fail 'the downloaded vhalla --help failed. Please report it at https://github.com/hraness/valhalla/issues'
    }

    Write-Host "-> Installing to $dir"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $destination = Join-Path $dir 'vhalla.exe'
    # A running vhalla.exe cannot be overwritten, but it can be renamed.
    Get-ChildItem -LiteralPath $dir -Filter 'vhalla.exe.old-*' -Force -ErrorAction SilentlyContinue |
      ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $destination) {
      $aside = "$destination.old-" + [Guid]::NewGuid().ToString('N')
      Move-Item -LiteralPath $destination -Destination $aside
      Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
    }
    Move-Item -LiteralPath $candidate -Destination $destination

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($userPath) { $entries = @($userPath.Split(';') | Where-Object { $_ }) }
    $onPath = $entries -contains $dir
    if (-not $onPath -and $env:VHALLA_NO_MODIFY_PATH -ne '1') {
      [Environment]::SetEnvironmentVariable('Path', (($entries + $dir) -join ';'), 'User')
      $env:Path = "$env:Path;$dir"
      $onPath = $true
      Write-Host "   Added $dir to your user PATH; open a new terminal to use it everywhere."
    }

    Write-Host ''
    Write-Host "vhalla $Version installed at $destination"
    if (-not $onPath) {
      Write-Host "  Note: $dir is not on your PATH. Add it:"
      Write-Host "    [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path', 'User') + ';$dir', 'User')"
    }
    Write-Host '  On Windows, vhalla runs identity and the member side of private rooms.'
    Write-Host '  For rooms, status, the demo and hosting, install the Linux build inside WSL:'
    Write-Host '    curl -fsSL https://vhalla.com/install.sh | sh'
    Write-Host "  Try it: vhalla identity init $env:USERPROFILE\valhalla\identity"
    Write-Host "  Next: $Guide"
  } finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}
