#include "memory.h"

LPVOID m_malloc(SIZE_T Size)
{
	LPVOID mem = malloc(Size);
	memset(mem, 0, Size);
	return mem;
}

LPVOID
memory::Alloc(SIZE_T Size) {
	return malloc(Size);
}

VOID
memory::Free(LPVOID Memory) {
	free(Memory);
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