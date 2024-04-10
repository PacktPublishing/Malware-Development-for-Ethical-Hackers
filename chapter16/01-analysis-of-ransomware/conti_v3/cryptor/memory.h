#pragma once
#include "common.h"

LPVOID m_malloc(SIZE_T Size);

namespace memory {

	LPVOID Alloc(SIZE_T Size);
	VOID Free(LPVOID Memory);
	VOID Copy(PVOID pDst, CONST PVOID pSrc, size_t size);

}