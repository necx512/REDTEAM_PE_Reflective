#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>

/*
WINDOWS LINUX
WORD	short	2 bytes
ULONG_PTR
SIZE_T
*/

// main.c

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

struct pe_structs
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER secHeader;
	PIMAGE_DATA_DIRECTORY dataDirectory;
};


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
ListDllFunctions(const unsigned char* dllPath, LPVOID baseAddress_infile, LPVOID baseAddress_inmem, BOOL do_patch);

void ListLoadedModules();
int patch_etw(LPVOID baseAddress_inmem);
int patch_amsi(LPVOID baseAddress_inmem);
int main_unhook(int argc, char* argv[]);


//custom_mimikatz.h
BOOL isElevatedProcess();
DWORD GetProcessIDByName(const char* processName);
BOOL setPrivilege();
int main_mimikatz(int argc, char* argv[]);

unsigned char* get_file(unsigned char* filename, size_t* ret_size);


// PE helper
struct pe_structs get_structs_from_baseAddr(void* baseaddr);
PVOID convert_RVA_to_virtualAddressInMem(PVOID* baseaddr_inmem, PVOID* PVA);
PVOID convert_RVA_to_virtualAddressInFile(PVOID* baseaddr_infile, PVOID* PVA);
PVOID get_section_by_name_InFile(PVOID* baseaddr_infile, DWORD* size, unsigned char* name_of_wanted_section);
PVOID get_section_by_name_InMem(PVOID* baseaddr_inmem, DWORD* size, unsigned char* name_of_wanted_section);
BOOL is_RVA_in_text_section_InFile(PVOID* baseaddr_infile, PVOID* RVA);
BOOL is_RVA_in_text_section_InMem(PVOID* baseaddr_inmem, PVOID* RVA);

