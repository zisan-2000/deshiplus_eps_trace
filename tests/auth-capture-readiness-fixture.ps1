[CmdletBinding()]
param()

$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$temporary=Join-Path $root ('tmp\auth-readiness-test-'+[Guid]::NewGuid().ToString('N'))
$pcap=Join-Path $temporary 'zero-packet.pcapng'
try {
  Import-Module (Join-Path $root 'scripts\AuthCaptureReadiness.psm1') -Force -ErrorAction Stop
  $null=New-Item -ItemType Directory -Path $temporary -Force
  $bytes=New-Object byte[] 48
  [BitConverter]::GetBytes([uint32]0x0a0d0d0a).CopyTo($bytes,0)
  [BitConverter]::GetBytes([uint32]28).CopyTo($bytes,4)
  [BitConverter]::GetBytes([uint32]0x1a2b3c4d).CopyTo($bytes,8)
  [BitConverter]::GetBytes([uint32]1).CopyTo($bytes,12)
  [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($bytes,16)
  [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($bytes,20)
  [BitConverter]::GetBytes([uint32]28).CopyTo($bytes,24)
  [BitConverter]::GetBytes([uint32]1).CopyTo($bytes,28)
  [BitConverter]::GetBytes([uint32]20).CopyTo($bytes,32)
  [BitConverter]::GetBytes([uint32]1).CopyTo($bytes,36)
  [BitConverter]::GetBytes([uint32]65535).CopyTo($bytes,40)
  [BitConverter]::GetBytes([uint32]20).CopyTo($bytes,44)
  [IO.File]::WriteAllBytes($pcap,$bytes)
  $structure=Get-EpsPcapngStructure -Path $pcap
  $zeroPacket=Get-EpsCaptureReadinessDecision -Structure $structure -InterfaceInventoryCompleted $true -Interface5Matched $true `
    -ProcessStarted $true -ProcessRunning $true -StderrSignalObserved $false -ElapsedMs 25 -TimeoutMs 8000
  $missing=Get-EpsPcapngStructure -Path (Join-Path $temporary 'missing.pcapng')
  $timeout=Get-EpsCaptureReadinessDecision -Structure $missing -InterfaceInventoryCompleted $true -Interface5Matched $true `
    -ProcessStarted $true -ProcessRunning $true -StderrSignalObserved $true -ElapsedMs 8000 -TimeoutMs 8000
  [pscustomobject]@{
    zeroPacketReady=$zeroPacket.ready
    readyWithoutPackets=$zeroPacket.diagnostics.readyWithoutPackets
    bannerRequired=($zeroPacket.diagnostics.packetRequiredForReadiness -or -not $zeroPacket.ready)
    packetBlockCount=$structure.packetBlockCount
    timeoutReady=$timeout.ready
    timeoutState=$timeout.state
    timeoutHasHeader=$timeout.diagnostics.interfaceDescriptionObserved
  }|ConvertTo-Json -Compress
} finally {
  if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Recurse -Force}
}
