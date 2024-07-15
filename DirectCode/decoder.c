#include <Windows.h>
#include "decoder.h"

void decode(unsigned char* buf, size_t size) {
	for (size_t i = 0; i < size; ++i) {
		buf[i] = buf[i] - 1;
	}
}