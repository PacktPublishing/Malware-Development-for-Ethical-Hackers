#include "logs.h"

STATIC CRITICAL_SECTION g_CritSec;
STATIC HANDLE g_LogHandle = INVALID_HANDLE_VALUE;

VOID
logs::Init(LPCWSTR LogFile)
{
	pInitializeCriticalSection(&g_CritSec);
	g_LogHandle = pCreateFileW(
		LogFile,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_FLAG_WRITE_THROUGH,
		NULL);

	pSetFilePointer(g_LogHandle, 0, NULL, FILE_END);
}

VOID
logs::Write(LPCWSTR Format, ...)
{
	if (g_LogHandle != INVALID_HANDLE_VALUE) {

		va_list Args;
		WCHAR Buffer[1024];

		va_start(Args, Format);

		RtlSecureZeroMemory(Buffer, sizeof(Buffer));
		INT Size = pwvsprintfW(Buffer, Format, Args);

		va_end(Args);

		if (Size > 0) {

			LPCWSTR clrf = OBFW(L"\r\n");
			Size *= sizeof(WCHAR);
			DWORD dwWritten;

			pEnterCriticalSection(&g_CritSec);
			{

				WCHAR TimeBuffer[128];
				SYSTEMTIME st;
				GetLocalTime(&st);
				INT TimeSize = wsprintfW(TimeBuffer, OBFW(L"[%02d:%02d:%02d] "), st.wHour, st.wMinute, st.wSecond);

				if (TimeSize) {
					pWriteFile(g_LogHandle, TimeBuffer, TimeSize * sizeof(WCHAR), &dwWritten, NULL);
				}

				pWriteFile(g_LogHandle, Buffer, Size, &dwWritten, NULL);
				pWriteFile(g_LogHandle, clrf, 4, &dwWritten, NULL);

			}
			pLeaveCriticalSection(&g_CritSec);

		}

	}
}