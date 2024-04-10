#include "global_parameters.h"

STATIC WCHAR g_Extention[7] = L".EXTEN";
STATIC CHAR g_DecryptNote[2048] = "__DECRYPT_NOTE__";
STATIC CHAR g_MutexName[65] = "__MUTEX_NAME__";

PWCHAR 
global::GetExtention()
{
	return g_Extention;
}

PCHAR 
global::GetDecryptNote(__in PDWORD pdwDecryptNote)
{
	DWORD dwLength = lstrlenA(g_DecryptNote);
	*pdwDecryptNote = dwLength;
	return g_DecryptNote;

}

PCHAR
global::GetMutexName()
{
	return g_MutexName;
}