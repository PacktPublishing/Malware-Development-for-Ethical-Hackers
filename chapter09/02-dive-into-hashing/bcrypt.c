#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

int main() {
  const char *password = "mysupersecretpassword";
  const char *salt = "packt";
  NTSTATUS status;
  BYTE DerivedKey[64];

  BCRYPT_ALG_HANDLE handle;
  status = BCryptOpenAlgorithmProvider(&handle, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);

  if (status != 0) {
    printf("BCryptOpenAlgorithmProvider exited with error message %x\n", status);
    return 1;
  }

  status = BCryptDeriveKeyPBKDF2(handle, (PUCHAR)password, (ULONG)strlen(password), (PUCHAR)salt, (ULONG)strlen(salt), 2048, DerivedKey, sizeof(DerivedKey), 0);

  if (status != 0) {
    printf("BCryptDeriveKeyPBKDF2 exited with error message %x\n", status);
    return 1;
  }

  else
    printf("Operation completed successfully. Your encrypted key is in variable DerivedKey.\n");

  BCryptCloseAlgorithmProvider(handle, 0);

  // print the hash
  printf("Hash: %02x\n", DerivedKey);
  return 0;
}