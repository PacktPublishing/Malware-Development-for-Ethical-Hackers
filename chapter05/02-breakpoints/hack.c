/*
 * Malware Development for Ethical Hackers
 * hack.c - Anti-debugging tricks
 * check for breakpoints
 * author: @cocomelonc
*/
#include <windows.h>
#include <stdio.h>

DWORD CalcFuncCrc(PUCHAR funcBegin, PUCHAR funcEnd) {
  DWORD crc = 0;
  for (; funcBegin < funcEnd; ++funcBegin) {
    crc += *funcBegin;
  }
  return crc;
}

#pragma auto_inline(off)
VOID DebuggeeFunction() {
  int calc = 0;
  calc += 2;
  calc <<= 8;
  calc -= 3;
}

VOID DebuggeeFunctionEnd() {};

#pragma auto_inline(on)
DWORD g_origCrc = 0x2bd0;

int main() {
  DWORD crc = CalcFuncCrc((PUCHAR)DebuggeeFunction, (PUCHAR)DebuggeeFunctionEnd);
  if (g_origCrc != crc) {
    MessageBox(NULL, "Debugger!", "=^..^=", MB_OK);
    return -1;
  }
  MessageBox(NULL, "Meow!", "=^..^=", MB_OK);
  return 0;
}