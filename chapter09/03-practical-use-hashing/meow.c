/*
 * Malware Development for Ethical Hackers
 * meow.c
 * simple WINAPI call without hashing
 * author: @cocomelonc
*/
#include <windows.h>
#include <stdio.h>

int main() {
  MessageBoxA(NULL, "Meow-meow!","=^..^=", MB_OK);
  return 0;
}
