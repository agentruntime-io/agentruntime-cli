<#
.SYNOPSIS
  Install the AgentRuntime CLI on Windows (no admin rights, nothing else required).

.EXAMPLE
  irm https://github.com/agentruntime-io/agentruntime-cli/releases/latest/download/install.ps1 | iex

.NOTES
  Environment overrides:
    AGENTRUNTIME_VERSION       pin a release tag (default: latest)
    AGENTRUNTIME_INSTALL_DIR   install location (default: %LOCALAPPDATA%\agentruntime\bin)
    AGENTRUNTIME_CLI_BASE_URL  alternate release host
    AGENTRUNTIME_NO_MODIFY_PATH  set to 1 to leave your PATH untouched
#>
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$base = if ($env:AGENTRUNTIME_CLI_BASE_URL) { $env:AGENTRUNTIME_CLI_BASE_URL.TrimEnd('/') } else { "https://github.com/agentruntime-io/agentruntime-cli/releases" }
$installDir = if ($env:AGENTRUNTIME_INSTALL_DIR) { $env:AGENTRUNTIME_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "agentruntime\bin" }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  "AMD64" { "amd64" }
  "ARM64" { "arm64" }
  default { throw "Unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
# 32-bit PowerShell on 64-bit Windows reports x86 here
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") { $arch = "amd64" }
if ($env:PROCESSOR_ARCHITEW6432 -eq "ARM64") { $arch = "arm64" }

$asset = "agentruntime_windows_$arch.zip"
$prefix = if ($env:AGENTRUNTIME_VERSION) { "$base/download/$($env:AGENTRUNTIME_VERSION)" } else { "$base/latest/download" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("agentruntime-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $tmp | Out-Null
try {
  Write-Host "Downloading $asset ..."
  Invoke-WebRequest -UseBasicParsing "$prefix/$asset" -OutFile (Join-Path $tmp $asset)
  Invoke-WebRequest -UseBasicParsing "$prefix/checksums.txt" -OutFile (Join-Path $tmp "checksums.txt")

  $expected = $null
  foreach ($line in Get-Content (Join-Path $tmp "checksums.txt")) {
    $parts = $line -split '\s+'
    if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $asset) { $expected = $parts[0]; break }
  }
  if (-not $expected) { throw "No checksum listed for $asset" }
  $actual = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash
  if ($actual -ne $expected.ToUpper()) { throw "Checksum mismatch for $asset (expected $expected, got $actual)" }

  Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $tmp -Force
  New-Item -ItemType Directory -Force $installDir | Out-Null
  $dest = Join-Path $installDir "agentruntime.exe"
  if (Test-Path $dest) {
    # A running exe cannot be overwritten, but it can be renamed.
    Remove-Item "$dest.old" -Force -ErrorAction SilentlyContinue
    Move-Item $dest "$dest.old" -Force
  }
  Copy-Item (Join-Path $tmp "agentruntime.exe") $dest -Force

  # Short alias: a plain copy (symlinks need elevated rights on Windows).
  $aliasDest = Join-Path $installDir "agent.exe"
  if (Test-Path $aliasDest) {
    Remove-Item "$aliasDest.old" -Force -ErrorAction SilentlyContinue
    Move-Item $aliasDest "$aliasDest.old" -Force
  }
  Copy-Item (Join-Path $tmp "agentruntime.exe") $aliasDest -Force
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if (-not $env:AGENTRUNTIME_NO_MODIFY_PATH) {
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $entries = @(); if ($userPath) { $entries = $userPath -split ';' | Where-Object { $_ } }
  if ($entries -notcontains $installDir) {
    [Environment]::SetEnvironmentVariable("Path", (($entries + $installDir) -join ';'), "User")
    Write-Host "Added $installDir to your PATH (open a new terminal to pick it up)."
  }
  $env:Path = "$env:Path;$installDir"
}

Write-Host ""
& $dest version
Write-Host ""

# Another tool may already own the name "agent" (for example the Cursor CLI).
$others = @(Get-Command agent -All -ErrorAction SilentlyContinue |
  Where-Object { $_.Source -and ((Split-Path $_.Source -Parent) -ne $installDir) })
if ($others.Count -gt 0) {
  Write-Warning ("Another 'agent' command is already on your PATH:`n  " + (($others | ForEach-Object { $_.Source }) -join "`n  ") +
    "`n'agent' may run that one instead of this CLI, depending on PATH order. 'agentruntime' always runs this CLI.")
}
Write-Host "Next: agentruntime login   (short form: agent login)"
