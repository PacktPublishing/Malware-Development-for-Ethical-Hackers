/*
 * Malware Development for Ethical Hackers
 * hack.c - hashing Win32API functions
 * @cocomelonc
*/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

typedef UINT(CALLBACK* fnMessageBoxA)(
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);

// MurmurHash is a non-cryptographic hash function and was written by Austin Appleby.
// unsigned int MurmurHash2A(const void *key, size_t len, unsigned int seed) {
//   const unsigned int m = 0x5bd1e995;
//   const int r = 24;
//   unsigned int h = seed ^ len;

//   const unsigned char *data = (const unsigned char *)key;

//   while (len >= 4) {
//     unsigned int k = *(unsigned int *)data;

//     k *= m;
//     k ^= k >> r;
//     k *= m;

//     h *= m;
//     h ^= k;

//     data += 4;
//     len -= 4;
//   }

//   switch (len) {
//     case 3:
//       h ^= data[2] << 16;
//     case 2:
//       h ^= data[1] << 8;
//     case 1:
//       h ^= data[0];
//       h *= m;
//   };

//   h ^= h >> 13;
//   h *= m;
//   h ^= h >> 15;

//   return h;
// }

DWORD calcMyHash(char* data) {
  DWORD hash = 0x35;
  for (int i = 0; i < strlen(data); i++) {
    hash += data[i] + (hash << 1);
  }
  return hash;
}

static LPVOID getAPIAddr(HMODULE h, DWORD myHash) {
  PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)h;
  PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)h + img_dos_header->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)(
    (LPBYTE)h + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  PDWORD fAddr = (PDWORD)((LPBYTE)h + img_edt->AddressOfFunctions);
  PDWORD fNames = (PDWORD)((LPBYTE)h + img_edt->AddressOfNames);
  PWORD  fOrd = (PWORD)((LPBYTE)h + img_edt->AddressOfNameOrdinals);

  for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
    LPSTR pFuncName = (LPSTR)((LPBYTE)h + fNames[i]);

    if (calcMyHash(pFuncName) == myHash) {
      printf("successfully found! %s - %d\n", pFuncName, myHash);
      return (LPVOID)((LPBYTE)h + fAddr[fOrd[i]]);
    }
  }
  return nullptr;
}

int main() {
  HMODULE mod = LoadLibrary("user32.dll");
  LPVOID addr = getAPIAddr(mod, 17036696);
  printf("0x%p\n", addr);
  fnMessageBoxA myMessageBoxA = (fnMessageBoxA)addr;
  myMessageBoxA(NULL, "Meow-meow!","=^..^=", MB_OK);
  return 0;
}