Set-StrictMode -Version Latest
$script:UsedMerchantIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$script:UsedOrderIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$script:RequiredNames = @(
  'EPS_ENV', 'EPS_USERNAME', 'EPS_PASSWORD', 'EPS_HASH_KEY', 'EPS_MERCHANT_ID', 'EPS_STORE_ID',
  'EPS_TRACE_CUSTOMER_ORDER_ID', 'EPS_TRACE_MERCHANT_TRANSACTION_ID', 'EPS_TRACE_AMOUNT',
  'EPS_TRACE_SUCCESS_URL', 'EPS_TRACE_FAIL_URL', 'EPS_TRACE_CANCEL_URL',
  'EPS_TRACE_CUSTOMER_NAME', 'EPS_TRACE_CUSTOMER_EMAIL', 'EPS_TRACE_CUSTOMER_ADDRESS',
  'EPS_TRACE_CUSTOMER_CITY', 'EPS_TRACE_CUSTOMER_STATE', 'EPS_TRACE_CUSTOMER_POSTCODE',
  'EPS_TRACE_CUSTOMER_COUNTRY', 'EPS_TRACE_CUSTOMER_PHONE', 'EPS_TRACE_PRODUCT_NAME',
  'EPS_TRACE_CALLBACK_ORIGIN', 'EPS_TRACE_ECOMMERCE_ORIGINS'
)

function Get-EpsPreparationEnvironmentNames { return @($script:RequiredNames) }

function Read-EpsPrivateValue {
  param([string]$Name, [string]$Prompt, [scriptblock]$InputProvider)
  $secure = $null
  $pointer = [IntPtr]::Zero
  try {
    if ($null -ne $InputProvider) { $secure = & $InputProvider $Name $Prompt }
    else { $secure = Read-Host -Prompt $Prompt -AsSecureString }
    if ($secure -isnot [Security.SecureString]) { throw 'PRIVATE_INPUT_PROVIDER_MUST_RETURN_SECURESTRING' }
    if ($secure.Length -gt 4096) { throw 'PRIVATE_INPUT_TOO_LONG' }
    if ($secure.Length -eq 0) { return '' }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
  }
  finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($secure -is [Security.SecureString]) { $secure.Dispose() }
  }
}

function New-EpsSyntheticInputs {
  param([string]$Amount)
  if ($Amount -notmatch '^[0-9]{1,8}(\.[0-9]{1,2})?$') { throw 'AMOUNT_FORMAT_INVALID' }
  $money = [decimal]::Parse($Amount, [Globalization.CultureInfo]::InvariantCulture)
  if ($money -le 0) { throw 'AMOUNT_FORMAT_INVALID' }
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $random = New-Object byte[] 8
  try {
    $merchantId = $null; $orderId = $null
    for ($attempt = 0; $attempt -lt 8; $attempt++) {
      $rng.GetBytes($random)
      $suffix = ([BitConverter]::ToUInt64($random, 0) % [uint64]10000000000).ToString('D10', [Globalization.CultureInfo]::InvariantCulture)
      $merchantId = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString([Globalization.CultureInfo]::InvariantCulture) + $suffix
      $rng.GetBytes($random)
      $hex = [BitConverter]::ToString($random).Replace('-', '').ToLowerInvariant()
      $orderId = 'DPEPS-' + $merchantId + '-' + $hex
      if ($merchantId -match '^[0-9]{23}$' -and -not $script:UsedMerchantIds.Contains($merchantId) -and -not $script:UsedOrderIds.Contains($orderId)) { break }
      $merchantId = $null; $orderId = $null
    }
    if ($null -eq $merchantId -or $null -eq $orderId) { throw 'LOCAL_IDENTITY_GENERATION_FAILED' }
    $null = $script:UsedMerchantIds.Add($merchantId); $null = $script:UsedOrderIds.Add($orderId)
    return @{
      EPS_TRACE_MERCHANT_TRANSACTION_ID = $merchantId; EPS_TRACE_CUSTOMER_ORDER_ID = $orderId
      EPS_TRACE_AMOUNT = $money.ToString('0.00', [Globalization.CultureInfo]::InvariantCulture)
      EPS_TRACE_CUSTOMER_NAME = 'EPS Diagnostic Synthetic Customer'
      EPS_TRACE_CUSTOMER_EMAIL = 'eps-diagnostic@example.com'
      EPS_TRACE_CUSTOMER_ADDRESS = 'Synthetic Sandbox Address'
      EPS_TRACE_CUSTOMER_CITY = 'Synthetic City'; EPS_TRACE_CUSTOMER_STATE = 'Synthetic State'
      EPS_TRACE_CUSTOMER_POSTCODE = '0000'; EPS_TRACE_CUSTOMER_COUNTRY = 'Bangladesh'
      EPS_TRACE_CUSTOMER_PHONE = '00000000000'; EPS_TRACE_PRODUCT_NAME = 'Synthetic diagnostic item'
    }
  }
  finally { [Array]::Clear($random, 0, $random.Length); $rng.Dispose() }
}

function Invoke-EpsOfflineValidation {
  param([bool]$CheckEnvironment)
  $projectRoot = Split-Path -Parent $PSScriptRoot
  $nodeCommand = Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1
  $info = [Diagnostics.ProcessStartInfo]::new()
  $info.FileName = $nodeCommand.Source
  $info.WorkingDirectory = $projectRoot
  $info.UseShellExecute = $false; $info.CreateNoWindow = $true
  $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
  $guardPath = Join-Path $PSScriptRoot 'offline-validation-guard.cjs'
  $cliPath = Join-Path $projectRoot 'src\cli.mjs'
  $configPath = Join-Path $projectRoot 'config.eps.sandbox.local.json'
  $info.Arguments = '--require "{0}" "{1}" validate --config "{2}"' -f $guardPath, $cliPath, $configPath
  if ($CheckEnvironment) { $info.Arguments += ' --check-env' }
  $info.EnvironmentVariables.Clear()
  foreach ($name in @('Path', 'PATHEXT', 'SystemRoot', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432')) {
    $value = [Environment]::GetEnvironmentVariable($name, 'Process')
    if ($null -ne $value) { $info.EnvironmentVariables[$name] = $value }
  }
  if ($CheckEnvironment) {
    foreach ($name in $script:RequiredNames) {
      $value = [Environment]::GetEnvironmentVariable($name, 'Process')
      if ($null -ne $value) { $info.EnvironmentVariables[$name] = $value }
    }
  }
  $process = $null
  try {
    $process = [Diagnostics.Process]::Start($info)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(15000)) { $process.Kill(); $null = $process.WaitForExit(3000); throw 'OFFLINE_VALIDATION_TIMEOUT' }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $null = $stderrTask.GetAwaiter().GetResult() # Never display raw third-party errors.
    if ($stdout.Length -gt 65536) { throw 'OFFLINE_VALIDATION_OUTPUT_INVALID' }
    try { $result = $stdout | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'OFFLINE_VALIDATION_OUTPUT_INVALID' }
    if ($null -eq $result.PSObject.Properties['valid'] -or $null -eq $result.PSObject.Properties['networkEnabled'] -or
        $null -eq $result.PSObject.Properties['executionReady'] -or $null -eq $result.PSObject.Properties['environmentChecked'] -or
        $result.networkEnabled -ne $false -or $result.executionReady -ne $false -or
        $result.environmentChecked -ne $CheckEnvironment) { throw 'OFFLINE_VALIDATION_OUTPUT_INVALID' }
    $safeIssues = [Collections.Generic.List[string]]::new()
    foreach ($issue in @($result.issues)) {
      if ($issue -is [string] -and $issue -match '^(ENV_MISSING|ENV_INVALID|CALLBACK_URL_FORMAT_INVALID):(EPS_[A-Z0-9_]+)$' -and $script:RequiredNames -contains $Matches[2]) {
        $safeIssues.Add($issue)
      } elseif ($issue -is [string] -and $issue -match '^(AMOUNT_FORMAT_INVALID|MERCHANT_TRANSACTION_ID_FORMAT_INVALID|PREPARATION_ID_FORMAT_INVALID|PREPARATION_ID_CORRELATION_INVALID|PREPARATION_AMOUNT_MUST_BE_CANONICAL|STATIC_EPS_TOKEN_FORBIDDEN|HMAC_SHA512_SELF_TEST_FAILED|HMAC_SIGNING_REQUIREMENTS_INVALID|ECOMMERCE_ORIGIN_DENYLIST_INVALID|ECOMMERCE_ORIGIN_DENYLIST_REQUIRED|ECOMMERCE_CALLBACK_TARGET_FORBIDDEN|ECOMMERCE_CALLBACK_ROUTE_FORBIDDEN|ISOLATED_CALLBACK_ORIGIN_REQUIRED|CALLBACK_ORIGIN_MISMATCH|CALLBACK_PATH_OR_QUERY_FORBIDDEN|CALLBACK_PATH_INVALID|CALLBACK_URL_FORMAT_INVALID)$') {
        $safeIssues.Add($issue)
      } else { $safeIssues.Add('ENVIRONMENT_OR_CONFIG_VALIDATION_REJECTED') }
    }
    return [pscustomobject]@{ Valid = ($process.ExitCode -eq 0 -and $result.valid -eq $true)
      Issues = @($safeIssues.ToArray()); ExecutionReady = $false }
  }
  finally {
    $info.EnvironmentVariables.Clear()
    if ($null -ne $process) { $process.Dispose() }
  }
}

function Invoke-EpsSandboxEnvironmentPreparation {
  [CmdletBinding()]
  param([scriptblock]$InputProvider)
  $ErrorActionPreference = 'Stop'
  $values = @{}; $previous = @{}; $changed = $false; $approval = $null; $amount = $null; $synthetic = $null
  try {
    foreach ($name in @('EPS_TRACE_MERCHANT_TRANSACTION_ID', 'EPS_TRACE_CUSTOMER_ORDER_ID')) {
      if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name, 'Process'))) { throw 'EXISTING_DIAGNOSTIC_IDENTITY_REQUIRES_REVIEW' }
    }
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
      if ($entry.Key -match '^EPS_(?:(?:AUTH|ACCESS|BEARER)_)?(?:TOKEN|JWT)$' -and -not [string]::IsNullOrWhiteSpace([string]$entry.Value)) { throw 'STATIC_EPS_TOKEN_FORBIDDEN' }
    }
    if ($env:SSLKEYLOGFILE -or $env:NODE_TLS_REJECT_UNAUTHORIZED -eq '0' -or $env:NODE_OPTIONS -match '--tls-keylog(?:=|\s|$)') { throw 'UNSAFE_TLS_ENVIRONMENT' }
    $configCheck = Invoke-EpsOfflineValidation -CheckEnvironment $false
    if (-not $configCheck.Valid) { throw 'LOCAL_CONFIG_VALIDATION_FAILED' }
    $approval = Read-EpsPrivateValue 'CALLBACK_AVAILABILITY' 'Dedicated approved EPS Sandbox callback receiver available? Type APPROVED or BLOCKED (hidden)' $InputProvider
    if ($approval -cne 'APPROVED') { throw 'ISOLATED_CALLBACK_RECEIVER_UNAVAILABLE_OR_UNAPPROVED' }
    $values.EPS_TRACE_CALLBACK_ORIGIN = Read-EpsPrivateValue 'EPS_TRACE_CALLBACK_ORIGIN' 'Approved dedicated HTTPS callback origin (hidden)' $InputProvider
    $values.EPS_TRACE_ECOMMERCE_ORIGINS = Read-EpsPrivateValue 'EPS_TRACE_ECOMMERCE_ORIGINS' 'Complete ecommerce HTTPS origin denylist as JSON array (hidden)' $InputProvider
    foreach ($name in @('EPS_TRACE_SUCCESS_URL', 'EPS_TRACE_FAIL_URL', 'EPS_TRACE_CANCEL_URL')) {
      $values[$name] = Read-EpsPrivateValue $name ($name + ' exact approved URL; do not use ecommerce callbacks (hidden)') $InputProvider
    }
    foreach ($name in @('EPS_USERNAME', 'EPS_PASSWORD', 'EPS_HASH_KEY', 'EPS_MERCHANT_ID', 'EPS_STORE_ID')) {
      $values[$name] = Read-EpsPrivateValue $name ($name + ' issued Sandbox value; never paste a Postman sample (hidden)') $InputProvider
    }
    $amount = Read-EpsPrivateValue 'EPS_TRACE_AMOUNT' 'Approved positive BDT test amount (hidden)' $InputProvider
    $synthetic = New-EpsSyntheticInputs -Amount $amount
    foreach ($name in $synthetic.Keys) { $values[$name] = $synthetic[$name] }
    $values.EPS_ENV = 'sandbox'
    # Windows environment assignment can truncate NUL or replace invalid Unicode.
    # Reject before assignment so validation never signs a changed credential.
    $inputIssues = [Collections.Generic.List[string]]::new()
    foreach ($name in $script:RequiredNames) {
      $value = [string]$values[$name]
      if ($value -match '[\x00]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]' -or
          ($name -in @('EPS_USERNAME', 'EPS_PASSWORD', 'EPS_HASH_KEY', 'EPS_MERCHANT_ID', 'EPS_STORE_ID') -and $value -match '[\r\n]')) {
        $inputIssues.Add('ENV_INVALID:' + $name)
      }
    }
    if ($inputIssues.Count -gt 0) {
      $global:LASTEXITCODE = 1
      return [pscustomobject]@{ Success = $false; Published = $false; Code = 'PRIVATE_ENVIRONMENT_VALIDATION_FAILED'; Issues = @($inputIssues.ToArray()); ExecutionReady = $false }
    }
    foreach ($name in $script:RequiredNames) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $changed = $true
    foreach ($name in $script:RequiredNames) { [Environment]::SetEnvironmentVariable($name, [string]$values[$name], 'Process') }
    $validation = Invoke-EpsOfflineValidation -CheckEnvironment $true
    if (-not $validation.Valid) {
      return [pscustomobject]@{ Success = $false; Published = $false; Code = 'PRIVATE_ENVIRONMENT_VALIDATION_FAILED'; Issues = @($validation.Issues); ExecutionReady = $false }
    }
    $changed = $false
    $global:LASTEXITCODE = 0
    return [pscustomobject]@{ Success = $true; Published = $true; Code = 'PRIVATE_ENVIRONMENT_PREPARED'; Issues = @(); ExecutionReady = $false }
  } catch {
    $global:LASTEXITCODE = 1
    $known = @('EXISTING_DIAGNOSTIC_IDENTITY_REQUIRES_REVIEW', 'STATIC_EPS_TOKEN_FORBIDDEN', 'UNSAFE_TLS_ENVIRONMENT',
      'LOCAL_CONFIG_VALIDATION_FAILED', 'ISOLATED_CALLBACK_RECEIVER_UNAVAILABLE_OR_UNAPPROVED',
      'PRIVATE_INPUT_PROVIDER_MUST_RETURN_SECURESTRING', 'PRIVATE_INPUT_TOO_LONG', 'AMOUNT_FORMAT_INVALID', 'LOCAL_IDENTITY_GENERATION_FAILED',
      'OFFLINE_VALIDATION_TIMEOUT', 'OFFLINE_VALIDATION_OUTPUT_INVALID')
    $code = 'PRIVATE_ENVIRONMENT_PREPARATION_FAILED'
    if ($known -ccontains $_.Exception.Message) { $code = $_.Exception.Message }
    return [pscustomobject]@{ Success = $false; Published = $false; Code = $code; Issues = @(); ExecutionReady = $false }
  }
  finally {
    if ($changed) { foreach ($name in $script:RequiredNames) { [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process') } }
    foreach ($name in @($values.Keys)) { $values[$name] = $null }
    $values.Clear(); $previous.Clear(); $approval = $null; $amount = $null; $value = $null
    if ($null -ne $synthetic) { $synthetic.Clear(); $synthetic = $null }
    if ($changed) { $global:LASTEXITCODE = 1 }
  }
}

Export-ModuleMember -Function Invoke-EpsSandboxEnvironmentPreparation, Get-EpsPreparationEnvironmentNames
