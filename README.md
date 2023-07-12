# NtGetProcessMitigationPolicy 

Based on the research from the following link:
- https://unit42.paloaltonetworks.com/junctions-windows-redirection-trust-mitigation/

## Output
```
Debugging: C:\Users\p4\source\repos\NtGetProcessMitigationPolicy\x64\Debug\NtGetProcessMitigationPolicy.exe
Database file: Z:\TOOLING\TOOLS\snapshot_2022-06-15_20-02\release\x64\db\NtGetProcessMitigationPolicy.exe.dd64
Process Started: 00007FF68D810000 C:\Users\p4\source\repos\NtGetProcessMitigationPolicy\x64\Debug\NtGetProcessMitigationPolicy.exe
  "C:\Users\p4\source\repos\NtGetProcessMitigationPolicy\x64\Debug\NtGetProcessMitigationPolicy.exe"
  argv[0]: C:\Users\p4\source\repos\NtGetProcessMitigationPolicy\x64\Debug\NtGetProcessMitigationPolicy.exe
Breakpoint at 00007FF68D81100F (entry breakpoint) set!
DLL Loaded: 00007FFAFDB30000 C:\Windows\System32\ntdll.dll
DLL Loaded: 00007FFAFCBF0000 C:\Windows\System32\kernel32.dll
DLL Loaded: 00007FFAFB610000 C:\Windows\System32\KernelBase.dll
DLL Loaded: 00007FFAF5670000 C:\Windows\System32\apphelp.dll
System breakpoint reached!
INT3 breakpoint "entry breakpoint" at <ntgetprocessmitigationpolicy.EntryPoint> (00007FF68D81100F)!
DebugString: "[DEBUG] CustomEntry"
DebugString: "[INFO] Enabled SeDebugPrivilege"
DebugString: "PID: 1128, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 1516, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 1568, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2128, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2136, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2168, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2212, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2220, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2236, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2424, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2508, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2612, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2640, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2652, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2664, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2736, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2868, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2904, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3140, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3160, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3168, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3292, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3484, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3552, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3668, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3740, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 3832, PROCNAME: svchost.exe, AuditRedirectionTrust( 0 ),EnforceRedirectionTrust( 1 )"
DebugString: "PID: 3840, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4024, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4032, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4040, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4072, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 2568, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4224, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4240, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4364, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4372, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4380, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4512, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4696, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4928, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4120, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4688, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 4864, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 5148, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 5264, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 5304, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 5352, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 5432, PROCNAME: wlanext.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 5444, PROCNAME: conhost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 5452, PROCNAME: spoolsv.exe, AuditRedirectionTrust( 0 ),EnforceRedirectionTrust( 1 )"
DebugString: "PID: 5540, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6160, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6176, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6216, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6240, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6292, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6328, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6336, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6352, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6396, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6692, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 6984, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 7288, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 7612, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 10964, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 11052, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 11260, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 11048, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 11544, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 12184, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 12392, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 12608, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 17944, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 20132, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 14500, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 8896, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 10732, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 16248, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 16028, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 11396, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 38416, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 38624, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 39792, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 28952, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 40772, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 39084, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 25784, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 33448, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 43040, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 53808, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 26896, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
DebugString: "PID: 22572, PROCNAME: svchost.exe, AuditRedirectionTrust( 1 ),EnforceRedirectionTrust( 0 )"
Process stopped with exit code 0x1 (1)
Saving database to Z:\TOOLING\TOOLS\snapshot_2022-06-15_20-02\release\x64\db\NtGetProcessMitigationPolicy.exe.dd64 0ms
Debugging stopped!
```

## Info 
```c
/*
* Basic Runtime Checks = Default
* Enable C++ Exceptions = No
* Runtime Library = Multi-threaded DLL (/MD)
* 
* Additional Dependencies = $(ProjectDir)ntdllp.lib;%(AdditionalDependencies)
* Entry point = CustomEntry
* Generate debug info = No
* Ignore all default libraries = Yes (/NODEFAULTLIB)
* Show Progress = Display all progress messages (/VERBOSE)
* SubSystem = Console (/SUBSYSTEM:CONSOLE)
* 
C:\Users\p4\source\repos\NtGetProcessMitigationPolicy>dumpbin /imports C:\Users\p4\source\repos\NtGetProcessMitigationPolicy\x64\Debug\NtGetProcessMitigationPolicy.exe
Microsoft (R) COFF/PE Dumper Version 14.29.30145.0
Copyright (C) Microsoft Corporation.  All rights reserved.

Dump of file C:\Users\p4\source\repos\NtGetProcessMitigationPolicy\x64\Debug\NtGetProcessMitigationPolicy.exe

File Type: EXECUTABLE IMAGE

  Section contains the following imports:

    ntdll.dll
             140007000 Import Address Table
             1400070E0 Import Name Table
                     0 time date stamp
                     0 Index of first forwarder reference

                         937 memcpy
                         1F9 NtQuerySystemInformation
                          FD NtClose
                         1AC NtOpenProcess
                         1DD NtQueryInformationProcess
                          22 DbgPrint
                         3C4 RtlExitUserProcess
                         2D3 RtlAllocateHeap
                         3F6 RtlFreeHeap
                         2CE RtlAdjustPrivilege
*/
```