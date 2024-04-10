#pragma once
#include "../common.h"
#include "../queue.h"

namespace process_killer {

	typedef struct pid_ {

		DWORD dwProcessId;
		TAILQ_ENTRY(pid_) Entries;

	} PID, *PPID;
	
	typedef TAILQ_HEAD(, pid_) PID_LIST, * PPID_LIST;

	VOID GetWhiteListProcess(PPID_LIST PidList);

}