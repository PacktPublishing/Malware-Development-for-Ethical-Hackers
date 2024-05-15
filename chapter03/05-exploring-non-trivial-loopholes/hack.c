/*
 * Malware Development for Ethical Hackers
 * hack.c
 * evil app for windows persistence via
 * hijacking uninstall app
 * author: @cocomelonc
*/
#include <windows.h>
#pragma comment (lib, "user32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
  MessageBox(NULL, "Hello, Packt!", "=^..^=", MB_OK);
  return 0;
}
