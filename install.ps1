param(
  [string]$Version = "latest",
  [ValidateSet("core")][string]$Mode = "core"
)
$ErrorActionPreference = "Stop"
$Repo = if ($env:LAYERFAULT_GITHUB_REPO) { $env:LAYERFAULT_GITHUB_REPO } else { "izm1chael/layerfault" }
$Arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::Arm64) { "arm64" } else { "amd64" }
$Base = if ($Version -eq "latest") { "https://github.com/$Repo/releases/latest/download" } else { if (-not $Version.StartsWith("v")) { $Version = "v$Version" }; "https://github.com/$Repo/releases/download/$Version" }
$Asset = "layerfault-windows-$Arch.zip"
$Temp = Join-Path $env:TEMP "layerfault-install-$PID"
New-Item -ItemType Directory -Force -Path $Temp | Out-Null
try {
  $AssetPath = Join-Path $Temp $Asset
  $ChecksumPath = Join-Path $Temp "SHA256SUMS"
  Invoke-WebRequest "$Base/$Asset" -OutFile $AssetPath
  Invoke-WebRequest "$Base/SHA256SUMS" -OutFile $ChecksumPath
  $Expected = Get-Content $ChecksumPath | ForEach-Object {
    if ($_ -match '^([0-9a-fA-F]{64})\s+\*?(.+)$' -and $Matches[2] -eq $Asset) { $Matches[1].ToLowerInvariant() }
  } | Select-Object -First 1
  if (-not $Expected) { throw "No SHA-256 entry for $Asset in release SHA256SUMS" }
  $Actual = (Get-FileHash $AssetPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($Actual -ne $Expected) { throw "SHA-256 verification failed for $Asset" }
  Expand-Archive $AssetPath -DestinationPath $Temp -Force
  $Dest = Join-Path $env:LOCALAPPDATA "Layerfault\bin"
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  Copy-Item (Join-Path $Temp "layerfault.exe") (Join-Path $Dest "layerfault.exe") -Force
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (($userPath -split ';') -notcontains $Dest) {
    [Environment]::SetEnvironmentVariable("Path", (($userPath.TrimEnd(';') + ';' + $Dest).Trim(';')), "User")
  }
  Write-Host "Installed Layerfault to $Dest. Open a new terminal and run: layerfault doctor"
  Write-Host "Active Bubblewrap analysis is currently Linux-only."
} finally {
  Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
