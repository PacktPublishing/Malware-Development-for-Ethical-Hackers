/*
 * Malware Development for Ethical Hackers
 * simple process find logic
 * author: @cocomelonc
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// find process ID by process name
int findTargetProcess(const char *targetProcName) {

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
int main(int argc, char* argv[]) {
  int pid = 0; // process ID

  pid = findTargetProcess(argv[1]);
  if (pid) {
    printf("PID = %d\n", pid);
  }
  return 0;
}