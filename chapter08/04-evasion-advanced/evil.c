/*
 * Malware Development for Ethical Hackers
 * evil.cpp
 * simple DLL for DLL inject to process
 * author: @cocomelonc
 * copyright: PacktPub
*/

#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  nReason, LPVOID lpReserved) {
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    MessageBox(NULL, "Hello, Packt!", "=^..^=", MB_OK);
    break;
  case DLL_PROCESS_DETACH:
    break;
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
    break;
  }
  return TRUE;
}

