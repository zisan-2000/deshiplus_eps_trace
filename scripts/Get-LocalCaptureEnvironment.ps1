$ErrorActionPreference = 'Stop'
try {
  $adapters = @(Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid, Status)
  $driverPath = Join-Path $env:SystemRoot 'System32\drivers\npcap.sys'
  $driverVersion = $null
  if (Test-Path -LiteralPath $driverPath) { $driverVersion = (Get-Item -LiteralPath $driverPath).VersionInfo.FileVersion }
  $adminOnly = $null
  foreach ($keyPath in @('HKLM:\SOFTWARE\Npcap', 'HKLM:\SOFTWARE\WOW6432Node\Npcap')) {
    if (Test-Path -LiteralPath $keyPath) {
      $setting = Get-ItemPropertyValue -LiteralPath $keyPath -Name AdminOnly -ErrorAction SilentlyContinue
      if ($null -ne $setting) { $adminOnly = [int]$setting; break }
    }
  }
  $driverState = & (Join-Path $env:SystemRoot 'System32\sc.exe') query npcap 2>$null
  $driverRunning = ($LASTEXITCODE -eq 0) -and (($driverState -join ' ') -match 'STATE\s*:\s*4\b')
  $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  [ordered]@{
    adapters = $adapters
    npcapVersion = $driverVersion
    npcapRunning = $driverRunning
    npcapAdminOnly = $adminOnly
    processElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } | ConvertTo-Json -Depth 4 -Compress
} catch {
  [Console]::Error.WriteLine('{"error":"LOCAL_CAPTURE_ENVIRONMENT_INSPECTION_FAILED"}')
  exit 1
}
