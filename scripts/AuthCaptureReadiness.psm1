Set-StrictMode -Version Latest

function Get-U32([byte[]]$Bytes,[int]$Offset,[bool]$Little) {
  if($Little){return [BitConverter]::ToUInt32($Bytes,$Offset)}
  return [uint32](($Bytes[$Offset] -shl 24) -bor ($Bytes[$Offset+1] -shl 16) -bor ($Bytes[$Offset+2] -shl 8) -bor $Bytes[$Offset+3])
}

function Get-EpsPcapngStructure {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Path)
  $result=[ordered]@{fileObserved=$false;bytes=0;sectionHeaderObserved=$false;interfaceDescriptionObserved=$false;packetBlockCount=0;validPrefix=$false}
  if(-not [IO.File]::Exists($Path)){return [pscustomobject]$result}
  $result.fileObserved=$true;$stream=$null
  try {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $bytes=New-Object byte[] 65536
    $length=$stream.Read($bytes,0,$bytes.Length);$result.bytes=$stream.Length
    if($length -lt 28 -or $bytes[0] -ne 0x0a -or $bytes[1] -ne 0x0d -or $bytes[2] -ne 0x0d -or $bytes[3] -ne 0x0a){return [pscustomobject]$result}
    $little=$bytes[8] -eq 0x4d -and $bytes[9] -eq 0x3c -and $bytes[10] -eq 0x2b -and $bytes[11] -eq 0x1a
    $big=$bytes[8] -eq 0x1a -and $bytes[9] -eq 0x2b -and $bytes[10] -eq 0x3c -and $bytes[11] -eq 0x4d
    if(-not $little -and -not $big){return [pscustomobject]$result}
    $offset=0
    while($offset+12 -le $length){
      $blockType=Get-U32 $bytes $offset $little;$blockLength=Get-U32 $bytes ($offset+4) $little
      if($blockLength -lt 12 -or $blockLength%4 -ne 0 -or $offset+$blockLength -gt $length){return [pscustomobject]$result}
      if((Get-U32 $bytes ($offset+$blockLength-4) $little) -ne $blockLength){return [pscustomobject]$result}
      if($blockType -eq 0x0a0d0d0a){$result.sectionHeaderObserved=$true}
      elseif($blockType -eq 1 -and $blockLength -ge 20){$result.interfaceDescriptionObserved=$true}
      elseif($blockType -in @(2,3,6)){$result.packetBlockCount++}
      $offset+=$blockLength
    }
    $result.validPrefix=$result.sectionHeaderObserved -and $result.interfaceDescriptionObserved
    return [pscustomobject]$result
  } catch {return [pscustomobject]$result}
  finally {if($stream){$stream.Dispose()}}
}

function Get-EpsCaptureReadinessDecision {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]$Structure,
    [bool]$InterfaceInventoryCompleted,
    [bool]$Interface5Matched,
    [bool]$ProcessStarted,
    [bool]$ProcessRunning,
    [bool]$StderrSignalObserved,
    [int]$ElapsedMs,
    [int]$TimeoutMs
  )
  $ready=$InterfaceInventoryCompleted -and $Interface5Matched -and $ProcessStarted -and $ProcessRunning -and
    $Structure.sectionHeaderObserved -and $Structure.interfaceDescriptionObserved
  $state=if($ready){'READY'}elseif($ProcessStarted -and -not $ProcessRunning){'PROCESS_EXITED'}elseif($ElapsedMs -ge $TimeoutMs){'TIMEOUT'}else{'WAITING'}
  return [pscustomobject]@{
    ready=$ready;state=$state
    diagnostics=[ordered]@{
      readinessState=$state
      interfaceInventoryCompleted=$InterfaceInventoryCompleted;interface5Matched=$Interface5Matched
      processStarted=$ProcessStarted;processRunningAtReadiness=$ProcessRunning;stderrSignalObserved=$StderrSignalObserved
      pcapFileObserved=[bool]$Structure.fileObserved;sectionHeaderObserved=[bool]$Structure.sectionHeaderObserved
      interfaceDescriptionObserved=[bool]$Structure.interfaceDescriptionObserved
      packetRequiredForReadiness=$false;packetBlockObservedBeforeRequest=([int]$Structure.packetBlockCount -gt 0)
      readyWithoutPackets=($ready -and [int]$Structure.packetBlockCount -eq 0)
      pcapBytesBeforeRequest=[int64]$Structure.bytes;readinessElapsedMs=[Math]::Max(0,$ElapsedMs);readinessTimeoutMs=[Math]::Max(0,$TimeoutMs)
    }
  }
}

Export-ModuleMember -Function Get-EpsPcapngStructure,Get-EpsCaptureReadinessDecision
