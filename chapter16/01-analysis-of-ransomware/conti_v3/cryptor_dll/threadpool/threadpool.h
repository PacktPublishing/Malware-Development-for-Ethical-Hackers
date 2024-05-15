#pragma once
#include "../common.h"
#include "../api/getapi.h"
#include "../memory.h"

namespace threadpool {

	enum THREADPOOLS {

		LOCAL_THREADPOOL,
		NETWORK_THREADPOOL,
		BACKUPS_THREADPOOL

	};

	VOID Initialize();
	BOOL Create(INT ThreadPoolID, SIZE_T ThreadsCount);
	BOOL Start(INT ThreadPoolID);
	BOOL PutTask(INT ThreadPoolID, std::wstring Path);
	BOOL PutFinalTask(INT ThreadPoolID);
	BOOL IsActive(INT ThreadPoolID);
	VOID Wait(INT ThreadPoolID);
	


};