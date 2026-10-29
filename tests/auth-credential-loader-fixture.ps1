[CmdletBinding()]
param()

$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$temporary=Join-Path $root ('tmp\auth-env-test-'+[Guid]::NewGuid().ToString('N'))
$file=Join-Path $temporary '.env.local'
$result=[ordered]@{parsed=$false;specialCharacters=$false;authOnly=$false;conflictRejected=$false;duplicateRejected=$false;unknownRejected=$false;outputSanitized=$true}
try {
  Import-Module (Join-Path $root 'scripts\AuthCredentialLoader.psm1') -Force -ErrorAction Stop
  $null=New-Item -ItemType Directory -Path $temporary -Force
  $dummyLines=@(
    'EPS_USERNAME=SYNTHETIC_USER',
    'EPS_PASSWORD=p@ss word=#;$()!`''"&|<>[]{}',
    'EPS_HASH_KEY=SYNTHETIC==HASH#KEY;$literal',
    'EPS_MERCHANT_ID=SYNTHETIC_MERCHANT',
    'EPS_STORE_ID=SYNTHETIC_STORE'
  )
  [IO.File]::WriteAllText($file,($dummyLines -join "`r`n")+"`r`n",[Text.UTF8Encoding]::new($false))
  Protect-EpsCredentialFile -Path $file
  $parsed=Read-EpsCredentialFile -Path $file
  $resolved=Resolve-EpsAuthCredentials -FileValues $parsed -ProcessValues @{}
  $result.parsed=$parsed.Count -eq 5
  $result.specialCharacters=$resolved.EPS_PASSWORD -ceq 'p@ss word=#;$()!`''"&|<>[]{}' -and $resolved.EPS_HASH_KEY -ceq 'SYNTHETIC==HASH#KEY;$literal'
  $result.authOnly=@($resolved.Keys|Sort-Object) -join ',' -ceq 'EPS_HASH_KEY,EPS_PASSWORD,EPS_USERNAME'
  try{$null=Resolve-EpsAuthCredentials -FileValues $parsed -ProcessValues @{EPS_USERNAME='DIFFERENT_SYNTHETIC_USER'}}catch{$result.conflictRejected=$_.Exception.Message -eq 'AUTH_ONLY_CREDENTIAL_SOURCE_CONFLICT'}
  [IO.File]::WriteAllText($file,"EPS_USERNAME=A`r`nEPS_USERNAME=B`r`n",[Text.UTF8Encoding]::new($false))
  try{$null=Read-EpsCredentialFile -Path $file}catch{$result.duplicateRejected=$_.Exception.Message -eq 'AUTH_ONLY_ENV_FILE_INVALID'}
  [IO.File]::WriteAllText($file,"EPS_USERNAME=A`r`nUNEXPECTED_KEY=B`r`n",[Text.UTF8Encoding]::new($false))
  try{$null=Read-EpsCredentialFile -Path $file}catch{$result.unknownRejected=$_.Exception.Message -eq 'AUTH_ONLY_ENV_FILE_INVALID'}
  $result|ConvertTo-Json -Compress
} finally {
  if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Recurse -Force}
}
