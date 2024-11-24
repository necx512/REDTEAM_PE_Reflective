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

#define GDI_HANDLE_BUFFER_SIZE      34
typedef struct _PEBOVERRIDE
{
    BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
    BOOLEAN ReadImageFileExecOptions;   //
    BOOLEAN BeingDebugged;              //
    BOOLEAN BitField;                  // reserved for bitfields with system-specific flags

    HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;

    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    union {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };

    DWORD SystemReserved;
    DWORD  AtlThunkSListPtr32;
    PVOID ApiSetMap;

    PVOID TlsExpansionCounter;
    PVOID TlsBitmap;
    DWORD  TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE

    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    //
    // Useful information for LdrpInitialize

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    //
    // Passed up from MmCreatePeb from Session Manager registry key
    //

    LARGE_INTEGER CriticalSectionTimeout;
    PVOID HeapSegmentReserve;
    PVOID HeapSegmentCommit;
    PVOID HeapDeCommitTotalFreeThreshold;
    PVOID HeapDeCommitFreeBlockThreshold;

    //
    // Where heap manager keeps track of all heaps created for a process
    // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //

    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;

    //
    //
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;

    //
    // Following fields filled in by MmCreatePeb from system values and/or
    // image header. These fields have changed since Windows NT 4.0,
    // so use with caution
    //

    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;

    PVOID ImageSubsystemMinorVersion;
    PVOID ImageProcessAffinityMask;
    PVOID GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];

    // [...] - more fields are there: this is just a fragment of the PEB structure
} PEBOVERRIDE, * PPEBOVERRIDE;



NTSYSAPI NTSTATUS NTAPI RtlEnterCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);
NTSYSAPI NTSTATUS NTAPI RtlLeaveCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection);


void fix_peb(PVOID baseaddr);




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

