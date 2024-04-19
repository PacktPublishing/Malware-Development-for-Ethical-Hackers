/*
 * Malware Development for Ethical Hackers
 * hack2.c - Anti-debugging tricks
 * ProcessDebugFlags
 * author: @cocomelonc
*/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

typedef NTSTATUS(NTAPI *fNtQueryInformationProcess)(
  IN HANDLE           ProcessHandle,
  IN DWORD            ProcessInformationClass,
  OUT PVOID           ProcessInformation,
  IN ULONG            ProcessInformationLength,
  OUT PULONG          ReturnLength
);

// Function to check if a debugger is present
bool DebuggerCheck() {
  BOOL result;
  DWORD rProcDebugFlags;
  DWORD returned;
  const DWORD ProcessDebugFlags = 0x1f;
  HMODULE nt = LoadLibraryA("ntdll.dll");
  fNtQueryInformationProcess myNtQueryInformationProcess = (fNtQueryInformationProcess)
  GetProcAddress(nt, "NtQueryInformationProcess");
  myNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags,
    &rProcDebugFlags, sizeof(DWORD), &returned);
  result = BOOL(rProcDebugFlags == 0);
  return result;
}

// Function that simulates the main functionality
void hack() {
  MessageBox(NULL, "Meow!", "=^..^=", MB_OK);
}

int main() {
  // Check if a debugger is present
  if (DebuggerCheck()) {
    MessageBox(NULL, "Bow-wow!", "=^..^=", MB_OK);
    return 1;  // exit if a debugger is present
  }
  // Main functionality
  hack();
  return 0;
}
