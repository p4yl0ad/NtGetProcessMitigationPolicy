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

#include <phnt_windows.h>
#include <phnt.h>

/*
* EnableSeDebug
*
* Purpose:
*
* Enable SeDebugPrivilege for process
*
* bastardized version of this https://github.com/nettitude/DLLInjection/blob/master/Nettitude/Injection/SeDebugPrivilege.cpp
*/

BOOL EnableSeDebug(
	void
);

/*
* supGetProcessMitigationPolicy
*
* Purpose:
*
* Request process mitigation policy values.
*
* Thanks to hfiref0x for this (https://github.dev/hfiref0x/WinObjEx64/blob/master/Source/WinObjEx64/props/propBasic.c)
*/

BOOL supGetProcessMitigationPolicy(
	_In_ HANDLE hProcess,
	_In_ PROCESS_MITIGATION_POLICY Policy,
	_In_ SIZE_T Size,
	_Out_writes_bytes_(Size) PVOID Buffer
);

/*
* EnumProcesses
*
* Purpose:
*
* Take SystemProcessInformation snapshot and iterate over every process
* Open each process via PID and query ProcessRedirectionTrustPolicy
*
*/

BOOL EnumProcesses(
	void
);

/*
* CustomEntry
*
* Purpose:
*
* Custom main function
*
*/

void CustomEntry() {
	DbgPrint("[DEBUG] CustomEntry\n");

	//
	// Try and enable SeDebugPrivilege
	//

	if (FALSE == EnableSeDebug())
		RtlExitUserProcess(-1);

	//
	// Enum and check processes for ProcessRedirectionTrustPolicy mitigation
	//

	if (FALSE == EnumProcesses())
		RtlExitUserProcess(-1);
}

/*
* EnableSeDebug
*
* Purpose:
*
* Enable SeDebugPrivilege for process 
*
* bastardized version of this https://github.com/nettitude/DLLInjection/blob/master/Nettitude/Injection/SeDebugPrivilege.cpp
*/

BOOL EnableSeDebug()
{
	BOOLEAN SeDebugWasEnabled = FALSE;
	if (NT_SUCCESS(RtlAdjustPrivilege(
		SE_DEBUG_PRIVILEGE,
		TRUE,
		FALSE,
		&SeDebugWasEnabled
	))) {
		DbgPrint("[INFO] Enabled SeDebugPrivilege\n");
		return TRUE;
	} 
	DbgPrint("[FAIL] Failed to enable SeDebugPrivilege\n");
	return FALSE;
}

/*
* supGetProcessMitigationPolicy
*
* Purpose:
*
* Request process mitigation policy values.
*
* Thanks to hfiref0x for this 
*/

typedef struct _PROCESS_MITIGATION_POLICY_RAW_DATA {
	PROCESS_MITIGATION_POLICY Policy;
	ULONG Value;
} PROCESS_MITIGATION_POLICY_RAW_DATA, * PPROCESS_MITIGATION_POLICY_RAW_DATA;

BOOL supGetProcessMitigationPolicy(
	_In_ HANDLE hProcess,
	_In_ PROCESS_MITIGATION_POLICY Policy,
	_In_ SIZE_T Size,
	_Out_writes_bytes_(Size) PVOID Buffer
)
{
	ULONG Length = 0;
	PROCESS_MITIGATION_POLICY_RAW_DATA MitigationPolicy;

	if (Size == sizeof(DWORD)) {

		MitigationPolicy.Policy = (PROCESS_MITIGATION_POLICY)Policy;

		if (NT_SUCCESS(NtQueryInformationProcess(
			hProcess,
			ProcessMitigationPolicy,
			&MitigationPolicy,
			sizeof(PROCESS_MITIGATION_POLICY_RAW_DATA),
			&Length)))
		{
			RtlCopyMemory(Buffer, &MitigationPolicy.Value, Size);
			return TRUE;
		}
	}

	return FALSE;
}

/*
* EnumProcesses
*
* Purpose:
*
* Take SystemProcessInformation snapshot and iterate over every process
* Open each process via PID and query ProcessRedirectionTrustPolicy
*
*/

BOOL EnumProcesses()
{
	//
	// Kinda based off this but without CRT and using RtlAllocateHeap / RtlFreeHeap instead 
	// https://gist.github.com/hasherezade/c3f82fb3099fb5d1afd84c9e8831af1e
	//

	ULONG retLen = 0;

	//
	// check length of structure
	//

	if (!(NT_SUCCESS(NtQuerySystemInformation(
		SystemProcessInformation,
		0,
		0,
		&retLen
	))) && (retLen == 0)){
		DbgPrint("[FAIL] Failed to get the length of the SYSTEM_PROCESS_INFORMATION structure\n");
		return FALSE;
	}
	
	//
	// prepate suitable heap
	//

	const size_t bufLen = retLen;
	PVOID infoBuf = RtlAllocateHeap(
		RtlProcessHeap(),
		HEAP_ZERO_MEMORY,
		bufLen
	);

	if (infoBuf == INVALID_HANDLE_VALUE)
	{
		DbgPrint("Failed to allocate heap\n");
		return FALSE;
	}

	//
	// enumerate processes and iterate over the returned 
	//

	PSYSTEM_PROCESS_INFORMATION sys_info = (PSYSTEM_PROCESS_INFORMATION)infoBuf;
	if (NT_SUCCESS(NtQuerySystemInformation(
		SystemProcessInformation, 
		sys_info, 
		bufLen, 
		&retLen
	)))	{
		while (1) {
			
			//
			// If there is a UniqueProcessId in the iterations structure, print it.
			//

			if (sys_info->UniqueProcessId) {
				
				//
				// If there is a ImageName.Buffer aswell as the UniqueProcessId in the iterations structure, print it.
				//			

				if (sys_info->ImageName.Buffer) {

					//
					// Open the process now in order to query the protection
					//

					HANDLE hProcess = NULL;
					OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

					//
					// init basic object attributes
					//

					InitializeObjectAttributes(
						&ObjectAttributes, 
						NULL, 
						0, 
						NULL, 
						NULL
					);

					//
					// Fill struct to open with the PID we got from NtQuerySystemInformation
					//

					CLIENT_ID uPid = {0};
					uPid.UniqueProcess = sys_info->UniqueProcessId;

					if (!(NT_SUCCESS(NtOpenProcess(
						&hProcess,
						PROCESS_ALL_ACCESS,
						&ObjectAttributes,
						&uPid
					)))) {

						//
						// Do nothing as we can just skip this process
						//

						//DbgPrint("[FAIL] Failed to open ( PID: %d, PROCNAME: %ls ) process with PROCESS_ALL_ACCESS\n",
						//	(ULONG)sys_info->UniqueProcessId, 
						//	sys_info->ImageName.Buffer
						//	);
					}
					else {
						
						//
						// We have opened the process and we can now check for the mitigation
						//

						PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY RedirectionTrustPolicy;

						if (supGetProcessMitigationPolicy(hProcess,
							(PROCESS_MITIGATION_POLICY)ProcessRedirectionTrustPolicy,
							sizeof(PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY),
							&RedirectionTrustPolicy))
						{
							if (RedirectionTrustPolicy.Flags) {
								DbgPrint("PID: %d, PROCNAME: %ls, AuditRedirectionTrust( %d ),EnforceRedirectionTrust( %d )\n", 
									(ULONG)sys_info->UniqueProcessId, sys_info->ImageName.Buffer, 
									RedirectionTrustPolicy.AuditRedirectionTrust, RedirectionTrustPolicy.EnforceRedirectionTrust
								);
							}
						}

						//
						// Close the handle we got from opening the process
						//

						if (!(NT_SUCCESS(NtClose(
							hProcess
						)))) { 
							DbgPrint("[FAIL] Failed to close the handle ?!?!\n");

						}

					}

				}
			}

			DbgPrint("\n");

			//
			// If there isn't a nextentryoffset we are done iterating the lists, break and do cleanup
			//

			if (!sys_info->NextEntryOffset) {
				break;
			}
			sys_info = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)sys_info + sys_info->NextEntryOffset);
		}
	}

	//
	// Free the heap we allocated for the structures
	//

	RtlFreeHeap(
		RtlProcessHeap(),
		HEAP_ZERO_MEMORY,
		infoBuf
	);

	return TRUE;
}