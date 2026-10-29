param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
$stage=10
try {
  $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $target=[IO.Path]::GetFullPath($Directory)
  $allowed=$target.StartsWith((Join-Path $root '.private')+'\',[StringComparison]::OrdinalIgnoreCase) -or $target.StartsWith((Join-Path $root 'tmp')+'\',[StringComparison]::OrdinalIgnoreCase)
  if(-not $allowed){throw 'PATH_FORBIDDEN'}
  $stage=11
  $item=Get-Item -LiteralPath $target
  if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'PATH_FORBIDDEN'}
  $stage=12
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $icacls=Join-Path $env:SystemRoot 'System32\icacls.exe'
  & $icacls $target /inheritance:r /grant:r "*$sid`:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' *> $null
  if($LASTEXITCODE -ne 0){throw 'ACL_FAILED'}
} catch {exit $stage}
