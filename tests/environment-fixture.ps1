param([string]$Case)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '..\scripts\EpsSandboxEnvironment.psm1') -DisableNameChecking
$names = @(Get-EpsPreparationEnvironmentNames)
foreach ($name in $names + @('EPS_TOKEN','EPS_JWT','SSLKEYLOGFILE','NODE_OPTIONS','NODE_TLS_REJECT_UNAUTHORIZED')) { [Environment]::SetEnvironmentVariable($name,$null,'Process') }
$env:EPS_PASSWORD = 'SYNTHETIC_PRIOR_VALUE'
if ($Case -eq 'existing') { $env:EPS_TRACE_MERCHANT_TRANSACTION_ID = 'SYNTHETIC_EXISTING_ID' }
if ($Case -eq 'token') { $env:EPS_TOKEN = 'SYNTHETIC_STATIC_TOKEN' }
if ($Case -eq 'tls') { $env:SSLKEYLOGFILE = 'SYNTHETIC_FORBIDDEN_PATH' }
$script:prompts = [Collections.Generic.List[string]]::new()
$script:caseName = $Case
$provider = {
  param($name,$prompt)
  $script:prompts.Add($name)
  if ($script:caseName -eq 'plaintext') { return 'SYNTHETIC_PLAINTEXT_FORBIDDEN' }
  if ($script:caseName -eq 'throw') { throw 'SYNTHETIC_PRIVATE_EXCEPTION' }
  $value = switch ($name) {
    'CALLBACK_AVAILABILITY' { if ($script:caseName -eq 'blocked') {'BLOCKED'} else {'APPROVED'} }
    'EPS_TRACE_CALLBACK_ORIGIN' { 'https://callbacks.example.com' }
    'EPS_TRACE_ECOMMERCE_ORIGINS' { '["https://shop.example.com"]' }
    'EPS_TRACE_SUCCESS_URL' { if ($script:caseName -eq 'callback') {'https://shop.example.com/api/eps/success'} else {'https://callbacks.example.com/eps-trace/success'} }
    'EPS_TRACE_FAIL_URL' { 'https://callbacks.example.com/eps-trace/fail' }
    'EPS_TRACE_CANCEL_URL' { 'https://callbacks.example.com/eps-trace/cancel' }
    'EPS_USERNAME' { 'synthetic-user' }
    'EPS_PASSWORD' {
      if ($script:caseName -eq 'missing') {''}
      elseif ($script:caseName -eq 'credential') {"SYNTHETIC`nPRIVATE"}
      elseif ($script:caseName -eq 'nul') { 'SYNTHETIC' + [char]0 + 'PRIVATE' }
      elseif ($script:caseName -eq 'unicode') { [string][char]0xD800 }
      elseif ($script:caseName -eq 'long') { 'x' * 4097 }
      else {'synthetic-password'}
    }
    'EPS_HASH_KEY' { 'synthetic-utf8-key' }
    'EPS_MERCHANT_ID' { 'synthetic-merchant' }
    'EPS_STORE_ID' { 'synthetic-store' }
    'EPS_TRACE_AMOUNT' { if ($script:caseName -eq 'amount') {'1.234'} else {'010.5'} }
    default { throw 'UNEXPECTED_PROMPT' }
  }
  if ($value -eq '') { return [Security.SecureString]::new() }
  return ConvertTo-SecureString -String $value -AsPlainText -Force
}
$result = Invoke-EpsSandboxEnvironmentPreparation -InputProvider $provider
$complete = $true
foreach ($name in $names) { if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name,'Process'))) { $complete = $false } }
$identityValid = $env:EPS_TRACE_MERCHANT_TRANSACTION_ID -match '^[0-9]{23}$' -and $env:EPS_TRACE_CUSTOMER_ORDER_ID -cmatch ('^DPEPS-' + $env:EPS_TRACE_MERCHANT_TRANSACTION_ID + '-[a-f0-9]{16}$')
$repeatBlocked = $false
$unique = $false
if ($result.Success) {
  $before = $env:EPS_TRACE_MERCHANT_TRANSACTION_ID
  $again = Invoke-EpsSandboxEnvironmentPreparation -InputProvider $provider
  $repeatBlocked = -not $again.Success -and $again.Code -eq 'EXISTING_DIAGNOSTIC_IDENTITY_REQUIRES_REVIEW' -and $before -ceq $env:EPS_TRACE_MERCHANT_TRANSACTION_ID
  $env:EPS_TRACE_MERCHANT_TRANSACTION_ID = $null; $env:EPS_TRACE_CUSTOMER_ORDER_ID = $null
  $next = Invoke-EpsSandboxEnvironmentPreparation -InputProvider $provider
  $unique = $next.Success -and $before -cne $env:EPS_TRACE_MERCHANT_TRANSACTION_ID
}
[pscustomobject]@{ Result=$result; Names=$names; PromptCount=$script:prompts.Count; FirstPrompt=($script:prompts | Select-Object -First 1)
  Complete=$complete; IdentityValid=$identityValid; AmountCanonical=($env:EPS_TRACE_AMOUNT -ceq '10.50'); RepeatBlocked=$repeatBlocked; Unique=$unique
  PreviousRestored=($env:EPS_PASSWORD -ceq 'SYNTHETIC_PRIOR_VALUE'); NoCredentialPrompt=(-not $script:prompts.Contains('EPS_PASSWORD'))
} | ConvertTo-Json -Depth 6 -Compress
