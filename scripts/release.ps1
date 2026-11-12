<#
.SYNOPSIS
  Cross-compile agentruntime for all platforms and produce release archives + checksums.txt in ./dist.

.EXAMPLE
  ./scripts/release.ps1 -Version v0.1.0
#>
param(
  [string]$Version = "dev"
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$dist = Join-Path $root "dist"
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory $dist | Out-Null

$commit = "none"
try { $c = (git rev-parse --short HEAD 2>$null); if ($c) { $commit = $c.Trim() } } catch {}
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$pkg = "github.com/agentruntime-io/agentruntime-cli/internal/version"
$ldflags = "-s -w -X $pkg.Version=$Version -X $pkg.Commit=$commit -X $pkg.Date=$date"

$targets = @(
  @("windows", "amd64"), @("windows", "arm64"),
  @("darwin", "amd64"), @("darwin", "arm64"),
  @("linux", "amd64"), @("linux", "arm64")
)

$oldOS, $oldArch, $oldCgo = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
try {
  foreach ($t in $targets) {
    $os, $arch = $t
    $bin = if ($os -eq "windows") { "agentruntime.exe" } else { "agentruntime" }
    $stage = Join-Path $dist "stage_${os}_${arch}"
    New-Item -ItemType Directory $stage | Out-Null

    $env:GOOS = $os; $env:GOARCH = $arch; $env:CGO_ENABLED = "0"
    Write-Host "building $os/$arch"
    go build -trimpath -ldflags $ldflags -o (Join-Path $stage $bin) .
    if ($LASTEXITCODE -ne 0) { throw "build failed for $os/$arch" }

    if ($os -eq "windows") {
      $archive = Join-Path $dist "agentruntime_${os}_${arch}.zip"
      Compress-Archive -Path (Join-Path $stage $bin) -DestinationPath $archive
    } else {
      $archive = Join-Path $dist "agentruntime_${os}_${arch}.tar.gz"
      tar -czf $archive -C $stage $bin
      if ($LASTEXITCODE -ne 0) { throw "tar failed for $os/$arch" }
    }
    Remove-Item -Recurse -Force $stage
  }
} finally {
  $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $oldOS, $oldArch, $oldCgo
}

$lines = Get-ChildItem $dist -File | Where-Object { $_.Name -ne "checksums.txt" } | Sort-Object Name | ForEach-Object {
  "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
# LF endings, no BOM, so sha256sum -c and the installers can parse it.
[IO.File]::WriteAllText((Join-Path $dist "checksums.txt"), (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))

Write-Host "`nRelease artifacts in $dist ($Version, $commit):"
Get-ChildItem $dist | ForEach-Object { "  {0,-40} {1,8:N1} MB" -f $_.Name, ($_.Length / 1MB) }
