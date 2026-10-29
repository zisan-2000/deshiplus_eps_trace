[CmdletBinding()]
param()

$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'AuthCredentialLoader.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'AuthCaptureReadiness.psm1') -Force -ErrorAction Stop
$captureFilter='tcp port 443 and host sandboxpgapi.eps.com.bd'
$captureProcess=$null
$nodeProcess=$null
$values=@{}
$fileValues=@{}
$processValues=@{}
$confirmation=$null
$directory=$null
$requestDisposition='NOT_SENT'
$lastReadinessDecision=$null
$captureDiagnostics=[ordered]@{
  readinessState='NOT_STARTED';interfaceInventoryCompleted=$false;interface5Matched=$false;processStarted=$false
  processRunningAtReadiness=$false;stderrSignalObserved=$false;pcapFileObserved=$false;sectionHeaderObserved=$false
  interfaceDescriptionObserved=$false;packetRequiredForReadiness=$false;packetBlockObservedBeforeRequest=$false
  readyWithoutPackets=$false;pcapBytesBeforeRequest=0;readinessElapsedMs=0;readinessTimeoutMs=0
}

function Quote-NativeArgument([string]$Value) {
  if($Value -notmatch '[\s"]'){return $Value}
  return '"'+($Value -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1')+'"'
}

function New-CleanProcessInfo([string]$File,[string[]]$Arguments) {
  $info=[Diagnostics.ProcessStartInfo]::new()
  $info.FileName=$File
  $info.WorkingDirectory=$projectRoot
  $info.UseShellExecute=$false
  $info.CreateNoWindow=$true
  $info.RedirectStandardOutput=$true
  $info.RedirectStandardError=$true
  $info.Arguments=($Arguments|ForEach-Object {Quote-NativeArgument $_}) -join ' '
  $info.EnvironmentVariables.Clear()
  foreach($name in @('Path','PATHEXT','SystemRoot','WINDIR','COMSPEC','TEMP','TMP','ProgramFiles','ProgramFiles(x86)','ProgramW6432')){
    $value=[Environment]::GetEnvironmentVariable($name,'Process')
    if($null-ne $value){$info.EnvironmentVariables[$name]=$value}
  }
  return $info
}

function Start-OwnedProcess([Diagnostics.ProcessStartInfo]$Info) {
  try{return [Diagnostics.Process]::Start($Info)}
  catch {
    if($_.Exception -is [UnauthorizedAccessException] -or $_.Exception.NativeErrorCode -eq 5){throw 'AUTH_CAPTURE_TOOL_LAUNCH_DENIED'}
    throw 'AUTH_CAPTURE_TOOL_LAUNCH_FAILED'
  }
}

function Invoke-OwnedTool([string]$File,[string[]]$Arguments,[int]$TimeoutMs) {
  $process=Start-OwnedProcess (New-CleanProcessInfo $File $Arguments)
  try {
    $stdoutTask=$process.StandardOutput.ReadToEndAsync()
    $stderrTask=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit($TimeoutMs)){$process.Kill();$null=$process.WaitForExit(3000);throw 'AUTH_CAPTURE_TOOL_TIMEOUT'}
    $stdout=$stdoutTask.GetAwaiter().GetResult();$null=$stderrTask.GetAwaiter().GetResult()
    return [pscustomobject]@{ExitCode=$process.ExitCode;Stdout=$stdout}
  } finally {$process.Dispose()}
}

function New-SanitizedFailureReport([string]$Code,[string]$FailureStage,[string]$Disposition,[bool]$CaptureReady=$false,$Diagnostics=$null) {
  $attempts=if($Disposition -eq 'NOT_SENT'){0}else{1}
  $capture=if($CaptureReady){[ordered]@{ready=$true;interface='5';filter=$captureFilter;file='session.pcapng';format='pcapng';bytes=$null;packetCount=$null;readinessBeforeRequest=$true}}else{$null}
  return [ordered]@{
    schemaVersion=2;stage='STEP_7C_AUTH_ONLY';evidenceScope='EPS_SANDBOX_AUTH_ONLY';outcome='FAIL';code=$Code
    failureStage=$FailureStage;requestDisposition=$Disposition
    request=[ordered]@{method='POST';endpoint='https://sandboxpgapi.eps.com.bd/v1/Auth/GetToken';attempts=$attempts}
    response=[ordered]@{httpStatus=$null;authAccepted=$false}
    timing=[ordered]@{dnsMs=$null;tcpConnectMs=$null;tlsHandshakeMs=$null;firstByteMs=$null;totalMs=$null;tlsVerified=$false}
    capture=$capture
    captureDiagnostics=$Diagnostics
    security=[ordered]@{credentialsPrinted=$false;credentialsPersisted=$false;xHashPersisted=$false;tokenPersisted=$false;responseBodyPersisted=$false;tlsKeyLogging=$false;rawPayloadReport=$false}
    forbiddenOperations=[ordered]@{initialize=$false;status=$false;hostedPayment=$false;callbacks=$false;automaticRetries=0}
  }
}

function Save-SanitizedReport($Report) {
  if(-not $directory){return}
  $json=$Report|ConvertTo-Json -Depth 8
  [IO.File]::WriteAllText((Join-Path $directory 'combined-report.json'),$json+"`n",[Text.UTF8Encoding]::new($false))
}

try {
  $confirmation=Read-Host 'This sends exactly one EPS Sandbox AUTH request. Type AUTH-ONLY to continue'
  if($confirmation -cne 'AUTH-ONLY'){Write-Host 'BLOCKED: explicit AUTH-only confirmation was not supplied.';exit 1}

  $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ss-fffZ')+'_'+[Guid]::NewGuid().ToString()
  $directory=Join-Path $projectRoot (Join-Path 'evidence\auth-check' $stamp)
  $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
  $pcap=Join-Path $directory 'session.pcapng'

  try{$config=Get-Content -LiteralPath (Join-Path $projectRoot 'config.eps.sandbox.local.json') -Raw|ConvertFrom-Json -ErrorAction Stop}
  catch{throw 'AUTH_ONLY_CONFIGURATION_REJECTED'}
  if($config.capture.interface -ne '5' -or $config.capture.captureFilter -cne $captureFilter -or
    $config.capture.fileName -cne 'session.pcapng' -or $config.capture.format -cne 'pcapng' -or
    $config.capture.preservePcap -ne $true -or $config.capture.readinessRequired -ne $true -or
    $config.capture.abortOnFailure -ne $true -or $config.capture.tlsKeyLoggingEnabled -ne $false){throw 'AUTH_ONLY_CONFIGURATION_REJECTED'}
  $tshark=[string]$config.capture.tsharkPath
  if([string]::IsNullOrWhiteSpace($tshark)){throw 'AUTH_ONLY_CONFIGURATION_REJECTED'}

  try{$inventory=Invoke-OwnedTool $tshark @('-D') 15000}
  catch{if($_.Exception.Message -eq 'AUTH_CAPTURE_TOOL_LAUNCH_DENIED'){throw};throw 'AUTH_CAPTURE_INTERFACE_INVENTORY_FAILED'}
  $captureDiagnostics.interfaceInventoryCompleted=$inventory.ExitCode -eq 0
  $captureDiagnostics.interface5Matched=$inventory.ExitCode -eq 0 -and $inventory.Stdout -match '(?m)^5\.\s+\S+\s+\(Wi-Fi\)\s*$'
  $captureDiagnostics.readinessTimeoutMs=[int]$config.capture.readinessTimeoutMs
  if(-not $captureDiagnostics.interfaceInventoryCompleted -or -not $captureDiagnostics.interface5Matched){throw 'AUTH_CAPTURE_INTERFACE_INVENTORY_FAILED'}

  $captureArgs=@('-n','-i','5','-f',$captureFilter,'-a','duration:25','-F','pcapng','--update-interval','20','-w',$pcap,'-q')
  $captureInfo=New-CleanProcessInfo $tshark $captureArgs
  $captureProcess=Start-OwnedProcess $captureInfo
  $captureDiagnostics.processStarted=$true
  $stdoutTask=$captureProcess.StandardOutput.ReadToEndAsync()
  $stderrLines=[Collections.Concurrent.ConcurrentQueue[string]]::new()
  $stderrHandler=[Diagnostics.DataReceivedEventHandler]{param($sender,$eventArgs)if($null-ne $eventArgs.Data){$stderrLines.Enqueue($eventArgs.Data)}}
  $captureProcess.add_ErrorDataReceived($stderrHandler);$captureProcess.BeginErrorReadLine()
  $readinessStarted=[DateTime]::UtcNow;$deadline=$readinessStarted.AddMilliseconds([int]$config.capture.readinessTimeoutMs)
  $banner=$false
  while([DateTime]::UtcNow -lt $deadline){
    $line=$null
    while($stderrLines.TryDequeue([ref]$line)){if($line -match 'Capturing on\s'){$banner=$true}}
    $running=-not $captureProcess.HasExited
    $elapsed=[int](([DateTime]::UtcNow-$readinessStarted).TotalMilliseconds)
    $structure=Get-EpsPcapngStructure -Path $pcap
    $lastReadinessDecision=Get-EpsCaptureReadinessDecision -Structure $structure -InterfaceInventoryCompleted $true -Interface5Matched $true `
      -ProcessStarted $true -ProcessRunning $running -StderrSignalObserved $banner -ElapsedMs $elapsed -TimeoutMs ([int]$config.capture.readinessTimeoutMs)
    $captureDiagnostics=$lastReadinessDecision.diagnostics
    if(-not $running){throw 'AUTH_CAPTURE_EXITED_BEFORE_READY'}
    if($lastReadinessDecision.ready){break}
    Start-Sleep -Milliseconds 20
  }
  if(-not $lastReadinessDecision -or -not $lastReadinessDecision.ready){
    $structure=Get-EpsPcapngStructure -Path $pcap
    $lastReadinessDecision=Get-EpsCaptureReadinessDecision -Structure $structure -InterfaceInventoryCompleted $true -Interface5Matched $true `
      -ProcessStarted $true -ProcessRunning (-not $captureProcess.HasExited) -StderrSignalObserved $banner `
      -ElapsedMs ([int](([DateTime]::UtcNow-$readinessStarted).TotalMilliseconds)) -TimeoutMs ([int]$config.capture.readinessTimeoutMs)
    $captureDiagnostics=$lastReadinessDecision.diagnostics
    throw 'AUTH_CAPTURE_READINESS_TIMEOUT'
  }
  $readyAt=[DateTime]::UtcNow.ToString('o')

  $fileValues=Read-EpsCredentialFile -Path (Join-Path $projectRoot '.env.local')
  foreach($name in @('EPS_USERNAME','EPS_PASSWORD','EPS_HASH_KEY')){
    $processValues[$name]=[Environment]::GetEnvironmentVariable($name,'Process')
  }
  $values=Resolve-EpsAuthCredentials -FileValues $fileValues -ProcessValues $processValues
  $fileValues.Clear();$processValues.Clear()
  foreach($item in @(
    @{Name='EPS_USERNAME';Prompt='EPS Sandbox username'},
    @{Name='EPS_PASSWORD';Prompt='EPS Sandbox password'},
    @{Name='EPS_HASH_KEY';Prompt='EPS Sandbox hash key'})){
    if($values.ContainsKey($item.Name) -and -not [string]::IsNullOrEmpty([string]$values[$item.Name])){continue}
    $secure=Read-Host -Prompt $item.Prompt -AsSecureString
    $pointer=[IntPtr]::Zero
    try{
      if($secure.Length -lt 1 -or $secure.Length -gt 4096){throw 'AUTH_ONLY_PRIVATE_INPUT_INVALID'}
      $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
      $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
      if($plain -match '[\x00-\x1f\x7f]'){throw 'AUTH_ONLY_PRIVATE_INPUT_INVALID'}
      $values[$item.Name]=$plain
    } finally {
      if($pointer -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)}
      if($secure -is [Security.SecureString]){$secure.Dispose()}
    }
  }

  $node=(Get-Command node -CommandType Application -ErrorAction Stop|Select-Object -First 1)
  $nodeInfo=New-CleanProcessInfo $node.Source @((Join-Path $projectRoot 'src\auth-check-cli.mjs'))
  foreach($name in $values.Keys){$nodeInfo.EnvironmentVariables[$name]=$values[$name]}
  $nodeInfo.EnvironmentVariables['EPS_AUTH_ONLY_CONFIRMATION']='EPS_AUTH_ONLY_EXPLICITLY_AUTHORIZED'
  $nodeInfo.EnvironmentVariables['EPS_AUTH_CAPTURE_OWNER']='POWERSHELL_TSHARK_V1'
  $nodeInfo.EnvironmentVariables['EPS_AUTH_CAPTURE_DIRECTORY']=$directory
  $nodeInfo.EnvironmentVariables['EPS_AUTH_CAPTURE_INTERFACE']='5'
  $nodeInfo.EnvironmentVariables['EPS_AUTH_CAPTURE_FILTER']=$captureFilter
  $nodeInfo.EnvironmentVariables['EPS_AUTH_CAPTURE_READY_AT']=$readyAt
  $nodeProcess=Start-OwnedProcess $nodeInfo
  $nodeInfo.EnvironmentVariables.Clear();$values.Clear();$requestDisposition='UNCERTAIN'
  $nodeStdoutTask=$nodeProcess.StandardOutput.ReadToEndAsync();$nodeStderrTask=$nodeProcess.StandardError.ReadToEndAsync()
  if(-not $nodeProcess.WaitForExit(60000)){$nodeProcess.Kill();$null=$nodeProcess.WaitForExit(3000);throw 'AUTH_ONLY_RUN_TIMEOUT'}
  $nodeStdout=$nodeStdoutTask.GetAwaiter().GetResult();$null=$nodeStderrTask.GetAwaiter().GetResult()
  $nodeResult=$nodeStdout|ConvertFrom-Json -ErrorAction Stop
  if($nodeResult.outcome -notin @('PASS','FAIL') -or $nodeResult.code -notmatch '^[A-Z0-9_]+$' -or
    [IO.Path]::GetFullPath([string]$nodeResult.evidenceDirectory) -ne [IO.Path]::GetFullPath($directory)){throw 'AUTH_ONLY_OUTPUT_INVALID'}

  $captureFailure=$null
  if(-not $captureProcess.WaitForExit(32000)){$captureProcess.Kill();$null=$captureProcess.WaitForExit(3000);$captureFailure='AUTH_CAPTURE_STOP_TIMEOUT'}
  elseif($captureProcess.ExitCode -ne 0 -or -not (Get-EpsPcapngStructure -Path $pcap).validPrefix){$captureFailure='AUTH_CAPTURE_EXIT_OR_FORMAT_FAILED'}
  $line=$null;while($stderrLines.TryDequeue([ref]$line)){if($line -match 'Capturing on\s'){$banner=$true}}
  $captureDiagnostics.stderrSignalObserved=$banner
  $null=$stdoutTask.GetAwaiter().GetResult()
  $report=Get-Content -LiteralPath (Join-Path $directory 'combined-report.json') -Raw|ConvertFrom-Json -ErrorAction Stop
  $requestDisposition=[string]$report.requestDisposition
  if(-not $captureFailure){
    try{$read=Invoke-OwnedTool $tshark @('-n','-r',$pcap,'-T','fields','-e','frame.number') 10000}
    catch{$captureFailure='AUTH_CAPTURE_READ_FAILED'}
    if(-not $captureFailure -and $read.ExitCode -ne 0){$captureFailure='AUTH_CAPTURE_READ_FAILED'}
  }
  if(-not $captureFailure){
    $packetCount=@($read.Stdout -split '\r?\n'|Where-Object {$_}).Count
    $report.capture.bytes=(Get-Item -LiteralPath $pcap).Length
    $report.capture.packetCount=$packetCount
    $report.capture|Add-Member -NotePropertyName completedAt -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
  } else {
    $report.outcome='FAIL';$report.code=$captureFailure;$report.failureStage='CAPTURE_FINALIZATION'
    if($report.requestDisposition -notin @('NOT_SENT','UNCERTAIN','SENT')){$report.requestDisposition='UNCERTAIN'}
  }
  $report|Add-Member -NotePropertyName captureDiagnostics -NotePropertyValue $captureDiagnostics -Force
  Save-SanitizedReport $report
  Write-Host ('AUTH-only result: '+$report.outcome+' ('+$report.code+')')
  Write-Host ('Sanitized evidence directory: '+$directory)
  Write-Host 'No credential, x-hash, token or response body was printed or persisted.'
  if($report.outcome -eq 'PASS'){exit 0}else{exit 1}
} catch {
  $code=if($_.Exception.Message -match '^AUTH_(?:ONLY|CAPTURE)_[A-Z0-9_]+$'){$_.Exception.Message}else{'AUTH_ONLY_PREPARATION_OR_EXECUTION_FAILED'}
  $stage=if($code -eq 'AUTH_CAPTURE_INTERFACE_INVENTORY_FAILED'){'CAPTURE_INTERFACE_INVENTORY'}
    elseif($code -in @('AUTH_CAPTURE_TOOL_LAUNCH_DENIED','AUTH_CAPTURE_TOOL_LAUNCH_FAILED')){'CAPTURE_TOOL_LAUNCH'}
    elseif($code -like 'AUTH_CAPTURE_*' -and $requestDisposition -ne 'NOT_SENT'){'CAPTURE_FINALIZATION'}
    elseif($code -like 'AUTH_CAPTURE_*'){'CAPTURE_READINESS'}else{'REQUEST_PREPARATION'}
  $captureReady=$stage -notin @('CAPTURE_INTERFACE_INVENTORY','CAPTURE_TOOL_LAUNCH','CAPTURE_READINESS')
  $reportExists=$false
  if($directory){$reportExists=Test-Path -LiteralPath (Join-Path $directory 'combined-report.json')}
  if($reportExists){
    try{
      $failedReport=Get-Content -LiteralPath (Join-Path $directory 'combined-report.json') -Raw|ConvertFrom-Json -ErrorAction Stop
      $failedReport.outcome='FAIL';$failedReport.code=$code;$failedReport.failureStage=$stage
      if($failedReport.requestDisposition -notin @('NOT_SENT','UNCERTAIN','SENT')){$failedReport.requestDisposition=$requestDisposition}
      $failedReport|Add-Member -NotePropertyName captureDiagnostics -NotePropertyValue $captureDiagnostics -Force
      Save-SanitizedReport $failedReport
    } catch {}
  } else {Save-SanitizedReport (New-SanitizedFailureReport $code $stage $requestDisposition $captureReady $captureDiagnostics)}
  Write-Host ('FAIL: '+$code+' (details suppressed)')
  if($directory){Write-Host ('Sanitized evidence directory: '+$directory)}
  exit 1
} finally {
  $values.Clear();$fileValues.Clear();$processValues.Clear();$confirmation=$null
  if($captureProcess -is [Diagnostics.Process]){
    try{if(-not $captureProcess.HasExited){$captureProcess.Kill();$null=$captureProcess.WaitForExit(3000)}}catch{}
    $captureProcess.Dispose()
  }
  if($nodeProcess -is [Diagnostics.Process]){$nodeProcess.Dispose()}
}
