param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
trap { Write-Output ('::error::Owned fixture failure: '+$_.Exception.Message+'; line='+$_.InvocationInfo.ScriptLineNumber); exit 1 }
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Windows only; test never targets a game.'}
Add-Type -Path (Join-Path $Root 'Native.cs')
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class OwnFixtureMemory {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr n,uint t,uint p);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool VirtualProtect(IntPtr a,UIntPtr n,uint p,out uint old);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool VirtualFree(IntPtr a,UIntPtr n,uint t);
}
'@
$address=[IntPtr]::Zero;$handle=[IntPtr]::Zero
try {
 $address=[OwnFixtureMemory]::VirtualAlloc([IntPtr]::Zero,[UIntPtr]4096,0x3000,0x04)
 if($address -eq [IntPtr]::Zero){throw 'Own fixture allocation failed'}
 [byte[]]$bytes=0x90,0x90,0xc3,0x41,0x42,0x43,0x44,0x45
 [Runtime.InteropServices.Marshal]::Copy($bytes,0,$address,$bytes.Length)
 $old=[UInt32]0
 if(-not [OwnFixtureMemory]::VirtualProtect($address,[UIntPtr]4096,0x20,[ref]$old)){throw 'Own fixture protect failed'}
 $handle=[HardwareSnapshot.Native]::OpenProcess(0x1010,$false,$PID)
 if($handle -eq [IntPtr]::Zero){throw 'Own fixture read handle failed'}
 $read=[HardwareSnapshot.Native]::Read($handle,[UInt64]$address.ToInt64(),8,$true)
 if([Convert]::ToBase64String($read) -ne [Convert]::ToBase64String($bytes)){throw 'Native read mismatch'}
 if(-not [OwnFixtureMemory]::VirtualProtect($address,[UIntPtr]4096,0x120,[ref]$old)){throw 'Own guard protect failed'}
 $refused=$false
 try {[void][HardwareSnapshot.Native]::Read($handle,[UInt64]$address.ToInt64(),8,$true)}
 catch {$refused=($_.Exception.GetBaseException().Reason -eq 'GuardOrUnreadablePage')}
 if(-not $refused){throw 'Guard page was not refused'}
 Write-Output 'OwnedWindowsFixtureReadPassed=True; GuardPageRefused=True; GameTargeted=False'
} finally {
 if($handle -ne [IntPtr]::Zero){[void][HardwareSnapshot.Native]::CloseHandle($handle)}
 if($address -ne [IntPtr]::Zero){[void][OwnFixtureMemory]::VirtualFree($address,[UIntPtr]::Zero,0x8000)}
}