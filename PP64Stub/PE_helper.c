#include "header.h"

struct pe_structs get_structs_from_baseAddr(void* baseaddr) {
	struct pe_structs structs;

	structs.dosHeader = (PIMAGE_DOS_HEADER)baseaddr;
	if (structs.dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature.\n");
		return;
	}

	structs.ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)baseaddr + structs.dosHeader->e_lfanew);
	if (structs.ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT signature.\n");
		return;
	}

	if (structs.ntHeader->FileHeader.Machine == 0x14c) {
		printf("This is 32bits\n");
		exit(2);
	}
	else if (structs.ntHeader->FileHeader.Machine == 0x8664) {
		//printf("This is 64bits\n");
	}
	else {
		printf("Unknown\n");
		exit(0);
	}

	structs.secHeader = (PIMAGE_SECTION_HEADER)((SIZE_T)structs.ntHeader + sizeof(IMAGE_NT_HEADERS));

	structs.dataDirectory = structs.ntHeader->OptionalHeader.DataDirectory;

	return structs;


}

static DWORD convert_RVA_to_offsetInFile(PVOID* baseaddr_infile, PVOID* PVA) {
	unsigned long long VA = (unsigned long long)PVA;
	struct pe_structs structs_infile = get_structs_from_baseAddr(baseaddr_infile);


	for (int i = 0; i < structs_infile.ntHeader->FileHeader.NumberOfSections; ++i) {
		unsigned long long PointerToRawData = structs_infile.secHeader[i].PointerToRawData;
		size_t size_raw = structs_infile.secHeader[i].SizeOfRawData;
		unsigned long long PointerToRawData_end = PointerToRawData + size_raw;


		unsigned long long VirtualAddr = structs_infile.secHeader[i].VirtualAddress;
		size_t size_va = structs_infile.secHeader[i].Misc.VirtualSize;
		unsigned long long VirtualAddr_end = VirtualAddr + size_va;

		unsigned long long diff = PointerToRawData - VirtualAddr;
		
		if (VA >= VirtualAddr && VA < VirtualAddr_end) {
			DWORD ret = VA + diff;
			return ret;
		}
	}
	printf("OUTCH\n");
	exit(-2);
}

PVOID convert_RVA_to_virtualAddressInMem(PVOID* baseaddr_inmem, PVOID* PVA)
{
	unsigned long long baseaddr_inmem_ull = (unsigned long long)baseaddr_inmem;
	unsigned long long PVA_ull = (unsigned long long)PVA;
	return (PVOID)(baseaddr_inmem_ull + PVA_ull);
}

PVOID convert_RVA_to_virtualAddressInFile(PVOID* baseaddr_infile, PVOID* PVA)
{
	DWORD offset_in_file = convert_RVA_to_offsetInFile(baseaddr_infile, PVA);
	unsigned long long baseaddr_infile_ull = (unsigned long long)baseaddr_infile;
	return (PVOID)(baseaddr_infile_ull + offset_in_file);
}

PVOID get_section_by_name_InFile(PVOID* baseaddr_infile, DWORD* size, unsigned char* name_of_wanted_section) {
	struct pe_structs structs_infile = get_structs_from_baseAddr(baseaddr_infile);

	for (int i = 0; i < structs_infile.ntHeader->FileHeader.NumberOfSections; i++) {
		unsigned char sectionName[9] = { 0 };
		strncpy(sectionName, (unsigned char*)structs_infile.secHeader[i].Name, 8);
		if (strcmp(name_of_wanted_section, sectionName) == 0) {
			*size = structs_infile.secHeader[i].SizeOfRawData;
			return (PVOID)((ULONG_PTR)baseaddr_infile + structs_infile.secHeader[i].PointerToRawData);//TODO use convert function instead. keep in mind the type ULONG_PTR
		}
	}
}

PVOID get_section_by_name_InMem(PVOID* baseaddr_inmem, DWORD* size, unsigned char* name_of_wanted_section) {
	struct pe_structs structs_inmem = get_structs_from_baseAddr(baseaddr_inmem);

	for (int i = 0; i < structs_inmem.ntHeader->FileHeader.NumberOfSections; i++) {
		unsigned char sectionName[9] = { 0 };
		strncpy(sectionName, (unsigned char*)structs_inmem.secHeader[i].Name, 8);
		if (strcmp(name_of_wanted_section, sectionName) == 0) {
			*size = structs_inmem.secHeader[i].Misc.VirtualSize;
			return (PVOID)((ULONG_PTR)baseaddr_inmem + structs_inmem.secHeader[i].VirtualAddress);//TODO use convert function instead. keep in mind the type ULONG_PTR
		}
	}
}

BOOL is_RVA_in_text_section_InFile(PVOID* baseaddr_infile, PVOID* RVA) {
	DWORD size = 0;
	ULONG_PTR section_addr = (ULONG_PTR)get_section_by_name_InFile(baseaddr_infile, &size, ".text");
	ULONG_PTR section_addr_end = section_addr + size;
	ULONG_PTR addr = (ULONG_PTR)convert_RVA_to_virtualAddressInFile(baseaddr_infile, RVA);
	if (addr >= section_addr && addr < section_addr_end) {
		return TRUE;
	}
	return FALSE;
}

BOOL is_RVA_in_text_section_InMem(PVOID* baseaddr_inmem, PVOID* RVA) {
	DWORD size = 0;
	ULONG_PTR section_addr = (ULONG_PTR)get_section_by_name_InMem(baseaddr_inmem, &size, ".text");
	ULONG_PTR section_addr_end = section_addr + size;
	ULONG_PTR addr = (ULONG_PTR)convert_RVA_to_virtualAddressInMem(baseaddr_inmem, RVA);
	if (addr >= section_addr && addr < section_addr_end) {
		return TRUE;
	}
	return FALSE;
}