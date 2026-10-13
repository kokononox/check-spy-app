param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
trap {Write-Output ('::error::Owned page native failure: '+$_.Exception.Message+'; line='+$_.InvocationInfo.ScriptLineNumber);exit 1}
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Windows only; owned fixture only'}
Add-Type -Path (Join-Path $Root 'Query-Native.cs')
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class OwnPageFixture {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr n,uint t,uint p);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool VirtualProtect(IntPtr a,UIntPtr n,uint p,out uint old);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool VirtualFree(IntPtr a,UIntPtr n,uint t);
}
'@
$h=[IntPtr]::Zero;$a=[IntPtr]::Zero;$reserved=[IntPtr]::Zero
$page=New-Object UIntPtr -ArgumentList ([UInt32]4096)
try {
 $h=[PageStateOnly.Native]::OpenProcess(0x0400,$false,$PID)
 if($h -eq [IntPtr]::Zero){throw 'query-only handle failed'}
 $path=[PageStateOnly.Native]::ImagePath($h)
 $m=[PageStateOnly.Native]::MainModule($PID,[IO.Path]::GetFileName($path))
 if($m.Base -eq 0 -or $m.Bytes -lt 4096){throw 'native module snapshot invalid'}
 if(-not [PageStateOnly.Native]::IsActive($h)){throw 'own process not active'}
 $a=[OwnPageFixture]::VirtualAlloc([IntPtr]::Zero,$page,0x3000,0x04)
 if($a -eq [IntPtr]::Zero){throw 'fixture allocation failed'}
 $r=[PageStateOnly.Native]::Query($h,[UInt64]$a.ToInt64())
 if($r.State -ne 0x1000 -or $r.Protect -ne 4 -or $r.ReturnedStructureBytes -ne 48){throw 'commit structure mismatch'}
 $old=[UInt32]0
 if(-not [OwnPageFixture]::VirtualProtect($a,$page,0x104,[ref]$old)){throw 'own guard setup failed'}
 $r=[PageStateOnly.Native]::Query($h,[UInt64]$a.ToInt64())
 $again=[PageStateOnly.Native]::Query($h,[UInt64]$a.ToInt64())
 if(($r.Protect -band 0x100) -eq 0 -or ($again.Protect -band 0x100) -eq 0){throw 'query consumed guard flag'}
 if(-not [OwnPageFixture]::VirtualProtect($a,$page,1,[ref]$old)){throw 'own noaccess setup failed'}
 $r=[PageStateOnly.Native]::Query($h,[UInt64]$a.ToInt64())
 if($r.State -ne 0x1000 -or $r.Protect -ne 1){throw 'noaccess not distinguished'}
 $reserved=[OwnPageFixture]::VirtualAlloc([IntPtr]::Zero,$page,0x2000,1)
 if($reserved -eq [IntPtr]::Zero){throw 'own reserve failed'}
 $r=[PageStateOnly.Native]::Query($h,[UInt64]$reserved.ToInt64())
 if($r.State -ne 0x2000){throw 'reserve not distinguished'}
 Write-Output 'OwnedQueryOnlyWindowsPassed=True; ModuleSnapshotPassed=True; GuardFlagUnchanged=True; NoAccessAndReserveDistinguished=True; GameTargeted=False'
}finally{
 if($h -ne [IntPtr]::Zero){[void][PageStateOnly.Native]::CloseHandle($h)}
 if($a -ne [IntPtr]::Zero){[void][OwnPageFixture]::VirtualFree($a,[UIntPtr]::Zero,0x8000)}
 if($reserved -ne [IntPtr]::Zero){[void][OwnPageFixture]::VirtualFree($reserved,[UIntPtr]::Zero,0x8000)}
}