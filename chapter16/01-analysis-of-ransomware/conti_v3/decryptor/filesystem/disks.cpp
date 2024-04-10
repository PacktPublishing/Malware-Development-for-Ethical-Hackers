#include "filesystem.h"

INT
filesystem::EnumirateDrives(PDRIVE_LIST DriveList)
{
	INT Length = 0;
	INT DrivesCount = 0;
	DWORD DriveType = 0;
	TAILQ_INIT(DriveList);

	SIZE_T BufferLength = GetLogicalDriveStringsW(0, NULL);
	if (!BufferLength) {
		return 0;
	}

	LPWSTR Buffer = (LPWSTR)m_malloc((BufferLength + 1) * sizeof(WCHAR));
	if (!Buffer) {
		return 0;
	}

	GetLogicalDriveStringsW(BufferLength, Buffer);

	LPWSTR tempBuffer = Buffer;

	while (Length = lstrlenW(tempBuffer)) {

		PDRIVE_INFO DriveInfo = new DRIVE_INFO;
		if (!DriveInfo) {

			m_free(Buffer);
			return 0;

		}

		DriveInfo->RootPath = tempBuffer;
		TAILQ_INSERT_TAIL(DriveList, DriveInfo, Entries);

		DrivesCount++;
		tempBuffer += Length + 1;

	}

	m_free(Buffer);
	return DrivesCount;
}