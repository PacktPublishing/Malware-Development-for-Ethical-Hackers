#include "memory.h"

LPVOID
memory::Alloc(SIZE_T Size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

VOID
memory::Free(LPVOID Memory) {
	HeapFree(GetProcessHeap(), 0, Memory);
}

VOID
memory::Copy(PVOID pDst, CONST PVOID pSrc, size_t size)
{
	void* tmp = pDst;
	size_t wordsize = sizeof(size_t);
	unsigned char* _src = (unsigned char*)pSrc;
	unsigned char* _dst = (unsigned char*)pDst;
	size_t   len;
	for (len = size / wordsize; len--; _src += wordsize, _dst += wordsize)
		*(size_t*)_dst = *(size_t*)_src;

	len = size % wordsize;
	while (len--)
		*_dst++ = *_src++;
}