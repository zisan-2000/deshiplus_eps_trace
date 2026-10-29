Set-StrictMode -Version Latest

# Resolve the security module from this shell's own PSHOME. This avoids loading
# a PowerShell 7 module into Windows PowerShell (or the reverse) when PSModulePath
# contains entries for both hosts.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Force -ErrorAction Stop

$script:AllowedCredentialNames=@('EPS_USERNAME','EPS_PASSWORD','EPS_HASH_KEY','EPS_MERCHANT_ID','EPS_STORE_ID')
$script:AuthCredentialNames=@('EPS_USERNAME','EPS_PASSWORD','EPS_HASH_KEY')

function Test-EpsCredentialValue([AllowNull()][string]$Value) {
  return $null-eq $Value -or ($Value.Length -le 4096 -and $Value -notmatch '[\x00-\x1f\x7f]')
}

function Protect-EpsCredentialFile {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Path)
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'AUTH_ONLY_ENV_FILE_UNSAFE'}
  $current=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
  $administrators=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $acl=[Security.AccessControl.FileSecurity]::new()
  $acl.SetOwner($current)
  $acl.SetAccessRuleProtection($true,$false)
  foreach($identity in @($current,$system,$administrators)){
    $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,
      [Security.AccessControl.AccessControlType]::Allow)
    $null=$acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
}

function Assert-EpsCredentialFileSecurity {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Path)
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 32768){throw 'AUTH_ONLY_ENV_FILE_UNSAFE'}
  $acl=Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
  if(-not $acl.AreAccessRulesProtected){throw 'AUTH_ONLY_ENV_FILE_PERMISSIONS_UNSAFE'}
  $allowed=@(
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
    'S-1-5-18',
    'S-1-5-32-544'
  )
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
      $rule.IdentityReference.Value -notin $allowed){throw 'AUTH_ONLY_ENV_FILE_PERMISSIONS_UNSAFE'}
  }
  return $true
}

function Read-EpsCredentialFile {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Path)
  $result=@{}
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){return $result}
  $null=Assert-EpsCredentialFileSecurity -Path $Path
  try{
    $bytes=[IO.File]::ReadAllBytes((Get-Item -LiteralPath $Path -Force).FullName)
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $text=$utf8.GetString($bytes)
  } catch {throw 'AUTH_ONLY_ENV_FILE_INVALID'}
  if($text.Length -and $text[0] -eq [char]0xfeff){$text=$text.Substring(1)}
  foreach($line in [regex]::Split($text,'\r\n|\n|\r')){
    if([string]::IsNullOrWhiteSpace($line) -or $line -match '^\s*#'){continue}
    $match=[regex]::Match($line,'^[ \t]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
    if(-not $match.Success){throw 'AUTH_ONLY_ENV_FILE_INVALID'}
    $name=$match.Groups[1].Value;$value=$match.Groups[2].Value
    if($name -notin $script:AllowedCredentialNames -or $result.ContainsKey($name) -or -not (Test-EpsCredentialValue $value)){
      throw 'AUTH_ONLY_ENV_FILE_INVALID'
    }
    $result[$name]=$value
  }
  return $result
}

function Resolve-EpsAuthCredentials {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][hashtable]$FileValues,
    [Parameter(Mandatory=$true)][hashtable]$ProcessValues
  )
  $resolved=@{}
  foreach($name in $script:AuthCredentialNames){
    $fromFile=if($FileValues.ContainsKey($name)){[string]$FileValues[$name]}else{''}
    $fromProcess=if($ProcessValues.ContainsKey($name)){[string]$ProcessValues[$name]}else{''}
    if(-not (Test-EpsCredentialValue $fromFile) -or -not (Test-EpsCredentialValue $fromProcess)){throw 'AUTH_ONLY_CREDENTIAL_INPUT_INVALID'}
    if($fromFile.Length -and $fromProcess.Length -and $fromFile -cne $fromProcess){throw 'AUTH_ONLY_CREDENTIAL_SOURCE_CONFLICT'}
    if($fromFile.Length){$resolved[$name]=$fromFile}
    elseif($fromProcess.Length){$resolved[$name]=$fromProcess}
  }
  return $resolved
}

Export-ModuleMember -Function Protect-EpsCredentialFile,Assert-EpsCredentialFileSecurity,Read-EpsCredentialFile,Resolve-EpsAuthCredentials
