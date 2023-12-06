#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

void calcMD5(const BYTE *data, DWORD dataSize, BYTE *hash) {
  HCRYPTPROV hCryptProv = 0;
  HCRYPTHASH hHash = 0;

  // Acquire a cryptographic provider context handle
  if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    fprintf(stderr, "Error during CryptAcquireContext (provider): %x\n", GetLastError());
    return;
  }

  // Create the hash object
  if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
    fprintf(stderr, "Error during CryptCreateHash: %x\n", GetLastError());
    CryptReleaseContext(hCryptProv, 0);
    return;
  }

  // Hash the data
  if (!CryptHashData(hHash, data, dataSize, 0)) {
    fprintf(stderr, "Error during CryptHashData: %x\n", GetLastError());
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    return;
  }

  // Get the final hash value
  DWORD hashSize = 16; // MD5 produces a 128-bit (16-byte) hash
  if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
    fprintf(stderr, "Error during CryptGetHashParam: %x\n", GetLastError());
  }

  // Clean up
  CryptDestroyHash(hHash);
  CryptReleaseContext(hCryptProv, 0);
}

int main() {
  // Example data
  const char *inputData = "meow-meow";
  DWORD dataSize = (DWORD)strlen(inputData);

  // Allocate space for the MD5 hash (16 bytes)
  BYTE md5Hash[16];

  // Calculate the MD5 hash
  calcMD5((const BYTE *)inputData, dataSize, md5Hash);

  // Print the MD5 hash
  printf("MD5 Hash: ");
  for (DWORD i = 0; i < sizeof(md5Hash); i++) {
    printf("%02x", md5Hash[i]);
  }
  printf("\n");

  return 0;
}
