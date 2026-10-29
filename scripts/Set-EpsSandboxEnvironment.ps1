[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
try {
  Import-Module (Join-Path $PSScriptRoot 'EpsSandboxEnvironment.psm1') -ErrorAction Stop
  $result = Invoke-EpsSandboxEnvironmentPreparation
  if ($result.Success) {
    Write-Host 'PASS: private process environment and synthetic inputs passed offline validation.'
    Write-Host 'No credential, hash, transaction reference, callback URL or customer value was printed or saved.'
    Write-Host 'Values remain in this PowerShell process. Close this session to clear them.'
    Write-Host 'BLOCKED: callback ownership, hosted payment, durable tracking and STATUS retry safety remain unconfirmed. Trace stays disabled.'
    $global:LASTEXITCODE = 0
  } else {
    Write-Host ('BLOCKED: ' + $result.Code)
    foreach ($issue in $result.Issues) { Write-Host (' - ' + $issue) }
    Write-Host 'No new environment was published; prior process values were preserved.'
    $global:LASTEXITCODE = 1
  }
} catch {
  Write-Host 'FAIL: PRIVATE_ENVIRONMENT_PREPARATION_FAILED (details suppressed)'
  $global:LASTEXITCODE = 1
}
