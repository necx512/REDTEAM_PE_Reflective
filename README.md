# REDTEAM_PE_Reflective

Srcs:
https://github.com/NUL0x4C/AtomPePacker combined with https://github.com/NUL0x4C/Syscallslib [forked]
(can be usefull:  https://github.com/Unam3dd/WinLoader.git)

```
void write_protections(char* ImageBase, PIMAGE_SECTION_HEADER sections, WORD nsections, DWORD size_of_headers)
{
    DWORD i = 0, old_prot = 0, new_prot = 0;
    char* addr = NULL;

    VirtualProtect(ImageBase, size_of_headers, PAGE_READONLY, &old_prot);

    for (i = 0; i < nsections; i++) {

        addr = (ImageBase + sections[i].VirtualAddress);

        // Check if section has execute permission
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            new_prot = ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ);
        else
            new_prot = ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY);

        // Set permission of each section
        VirtualProtect(addr, sections[i].Misc.VirtualSize, new_prot, &old_prot);
    }
}
```
