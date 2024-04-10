#pragma once
#include "../common.h"
#include "../queue.h"

namespace network_scanner {


	typedef struct share_info_ {

		WCHAR wszSharePath[16000];
		TAILQ_ENTRY(share_info_) Entries;

	} SHARE_INFO, * PSHARE_INFO;


	typedef TAILQ_HEAD(share_list_, share_info_) SHARE_LIST, * PSHARE_LIST;

	VOID StartScan();
	VOID EnumShares(PWCHAR pwszIpAddress, PSHARE_LIST ShareList);
};