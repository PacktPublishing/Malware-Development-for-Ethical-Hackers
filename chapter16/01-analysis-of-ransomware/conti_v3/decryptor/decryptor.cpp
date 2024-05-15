#include "decryptor.h"
#include <wincrypt.h>

#pragma comment(lib, "Shlwapi.lib")

#define EXIT_COMPLETION_KEY (ULONG_PTR)666

STATIC HANDLE g_IocpHandle;
STATIC HANDLE g_Threads[32];
STATIC INT g_ThreadsNumber;
STATIC CONST DWORD BufferSize = 5242880;
STATIC CONST BYTE g_ContiPattern[16] = { 0xab, 0xff, 0x63, 0xa1, 0x6f, 0xa2 , 0x6e, 0x6e, 0xa3, 0x74, 0x69, 0xbf, 0x4c, 0xdd, 0xff, 0xa1 };

enum ENCRYPT_MODES {

	FULL_ENCRYPT = 0x24,
	PARTLY_ENCRYPT = 0x25,
	HEADER_ENCRYPT = 0x26

};

BOOL
decryptor::ChangeFileName(__in LPCWSTR OldName)
{
	LPWSTR NewName = (LPWSTR)memory::Alloc(32727);
	if (!NewName) {
		return FALSE;
	}

	lstrcpynW(NewName, OldName, lstrlenW(OldName) - 5);
	MoveFileW(OldName, NewName);
	memory::Free(NewName);
	return TRUE;
}

STATIC
BOOL
CheckContiPattern(
	__in decryptor::LPFILE_INFO FileInfo,
	__out PBOOL Error
)
{
	LARGE_INTEGER Pointer;
	Pointer.QuadPart = -16;

	if (!SetFilePointerEx(FileInfo->FileHandle, Pointer, NULL, FILE_END)) {

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

		if (!ReadFile(FileInfo->FileHandle, Buffer + Offset, BytesToRead, &BytesRead, NULL) || !BytesRead) {

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
ReadEncryptInfo(__in decryptor::LPFILE_INFO FileInfo)
{
	DWORD BytesRead;
	BOOL Success;
	LARGE_INTEGER Offset;
	BYTE Buffer[10];

	Offset.QuadPart = -534;
	if (!SetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_END)) {
		return FALSE;
	}

	Success = ReadFile(FileInfo->FileHandle, FileInfo->EncryptedKey, 524, &BytesRead, NULL);
	if (!Success || BytesRead != 524) {
		return FALSE;
	}

	Success = ReadFile(FileInfo->FileHandle, Buffer, 10, &BytesRead, NULL);
	if (!Success || BytesRead != 10) {
		return FALSE;
	}

	FileInfo->EncryptMode = Buffer[0];
	FileInfo->DataPercent = Buffer[1];
	memory::Copy(&FileInfo->OriginalFileSize, Buffer + 2, 8);

	Offset.QuadPart = 0;
	return SetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_BEGIN);
}

VOID
decryptor::CloseFile(__in decryptor::LPFILE_INFO FileInfo)
{
	if (FileInfo->FileHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(FileInfo->FileHandle);
		FileInfo->FileHandle = INVALID_HANDLE_VALUE;
	}

	RtlSecureZeroMemory(FileInfo->EncryptedKey, sizeof(FileInfo->EncryptedKey));
}

STATIC
BOOL
OpenFileDecrypt(__in decryptor::LPFILE_INFO FileInfo)
{
	FileInfo->FileHandle = CreateFileW(FileInfo->Filename,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	DWORD le = GetLastError();
	if (FileInfo->FileHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(FileInfo->FileHandle, &FileSize) ||
		!FileSize.QuadPart ||
		FileSize.QuadPart < 534)
	{

		CloseFile(FileInfo);
		return FALSE;

	}

	if (!ReadEncryptInfo(FileInfo))
	{

		CloseFile(FileInfo);
		return FALSE;

	}

	FileInfo->FileSize = FileInfo->OriginalFileSize;

	return TRUE;
}

STATIC
BOOL
WriteDecryptedData(
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

		if (!WriteFile(hFile, (LPBYTE)Buffer + Offset, BytesToWrite, &BytesWritten, NULL) || !BytesWritten) {

			return FALSE;

		}

		Offset += BytesWritten;
		TotalWritten += BytesWritten;
		BytesToWrite -= BytesWritten;

	}

	return TRUE;
}

STATIC
BOOL
DecryptHeader(
	__in decryptor::LPFILE_INFO FileInfo,
	__in LPBYTE Buffer,
	__in HCRYPTPROV CryptoProvider
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

		LONGLONG BytesLeft = BytesToEncrypt - TotalRead;
		BytesToRead = BytesLeft > BufferSize ? BufferSize : (DWORD)BytesLeft;

		Success = ReadFile(FileInfo->FileHandle, Buffer, BytesToRead, &BytesRead, NULL);
		if (!Success || !BytesRead) {
			break;
		}

		TotalRead += BytesRead;
		BytesToWrite = BytesRead;

		ECRYPT_decrypt_bytes(&FileInfo->CryptCtx, Buffer, Buffer, BytesRead);

		Offset.QuadPart = -((LONGLONG)BytesRead);
		if (!SetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
			break;
		}

		Success = WriteDecryptedData(FileInfo->FileHandle, Buffer, BytesToWrite);
		if (!Success) {
			break;
		}

	}

	return TRUE;
}

STATIC
BOOL
DecryptPartly(
	__in decryptor::LPFILE_INFO FileInfo,
	__in LPBYTE Buffer,
	__in HCRYPTPROV CryptoProvider,
	__in LONGLONG DataPercent
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
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 15:
		PartSize = (FileInfo->FileSize / 100) * 5;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 20:
		PartSize = (FileInfo->FileSize / 100) * 7;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 25:
		PartSize = (FileInfo->FileSize / 100) * 9;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 30:
		PartSize = (FileInfo->FileSize / 100) * 10;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 35:
		PartSize = (FileInfo->FileSize / 100) * 12;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 40:
		PartSize = (FileInfo->FileSize / 100) * 14;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 50:
		PartSize = (FileInfo->FileSize / 100) * 10;
		StepsCount = 5;
		StepSize = PartSize;
		break;

	case 60:
		PartSize = (FileInfo->FileSize / 100) * 20;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 70:
		PartSize = (FileInfo->FileSize / 100) * 23;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	case 80:
		PartSize = (FileInfo->FileSize / 100) * 27;
		StepsCount = 3;
		StepSize = (FileInfo->FileSize - (PartSize * 3)) / 2;
		break;

	default:
		return FALSE;
	}

	for (INT i = 0; i < StepsCount; i++) {

		TotalRead = 0;
		BytesToEncrypt = PartSize;

		if (i != 0) {

			Offset.QuadPart = StepSize;
			if (!SetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
				break;
			}

		}

		while (TotalRead < BytesToEncrypt) {

			LONGLONG BytesLeft = BytesToEncrypt - TotalRead;
			BytesToRead = BytesLeft > BufferSize ? BufferSize : (DWORD)BytesLeft;

			Success = ReadFile(FileInfo->FileHandle, Buffer, BytesToRead, &BytesRead, NULL);
			if (!Success || !BytesRead) {
				break;
			}

			TotalRead += BytesRead;
			BytesToWrite = BytesRead;

			ECRYPT_decrypt_bytes(&FileInfo->CryptCtx, Buffer, Buffer, BytesRead);

			Offset.QuadPart = -((LONGLONG)BytesRead);
			if (!SetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
				break;
			}

			Success = WriteDecryptedData(FileInfo->FileHandle, Buffer, BytesToWrite);
			if (!Success) {
				break;
			}

		}

	}

	return TRUE;
}

STATIC
BOOL
DecryptFull(
	__in decryptor::LPFILE_INFO FileInfo,
	__in LPBYTE Buffer,
	__in HCRYPTPROV CryptoProvider
)
{
	BOOL Success = FALSE;
	DWORD BytesRead = 0;
	DWORD BytesToRead = 0;
	DWORD BytesToWrite = 0;
	LONGLONG TotalRead = 0;
	LONGLONG BytesToEncrypt;
	LARGE_INTEGER Offset;

	BytesToEncrypt = FileInfo->OriginalFileSize;

	while (TotalRead < BytesToEncrypt) {

		LONGLONG BytesLeft = BytesToEncrypt - TotalRead;
		BytesToRead = BytesLeft > BufferSize ? BufferSize : (DWORD)BytesLeft;

		Success = ReadFile(FileInfo->FileHandle, Buffer, BytesToRead, &BytesRead, NULL);
		if (!Success || !BytesRead) {
			break;
		}

		TotalRead += BytesRead;
		BytesToWrite = BytesRead;

		ECRYPT_decrypt_bytes(&FileInfo->CryptCtx, Buffer, Buffer, BytesRead);

		Offset.QuadPart = -((LONGLONG)BytesRead);
		if (!SetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_CURRENT)) {
			break;
		}

		Success = WriteDecryptedData(FileInfo->FileHandle, Buffer, BytesToWrite);
		if (!Success) {
			break;
		}

	}

	return TRUE;
}

BOOL
decryptor::Decrypt(
	__in decryptor::LPFILE_INFO FileInfo,
	__in LPBYTE Buffer,
	__in HCRYPTPROV CryptoProvider,
	__in HCRYPTKEY PrivateKey
)
{
	DWORD BytesToRead = 0;
	LONGLONG TotalRead = 0;
	BOOL Result = FALSE;

	if (!OpenFileDecrypt(FileInfo)) {
		return FALSE;
	}

	DWORD EncryptedKeySize = 524;
	if (!CryptDecrypt(PrivateKey, 0, TRUE, 0, FileInfo->EncryptedKey, &EncryptedKeySize)) {
		return FALSE;
	}

	memory::Copy(FileInfo->ChachaKey, FileInfo->EncryptedKey, 32);
	memory::Copy(FileInfo->ChachaIV, FileInfo->EncryptedKey + 32, 8);
	ECRYPT_keysetup(&FileInfo->CryptCtx, FileInfo->ChachaKey, 256, 64);
	ECRYPT_ivsetup(&FileInfo->CryptCtx, FileInfo->ChachaIV);

	if (FileInfo->EncryptMode == FULL_ENCRYPT) {

		Result = DecryptFull(FileInfo, Buffer, CryptoProvider);

	}
	else if (FileInfo->EncryptMode == PARTLY_ENCRYPT) {

		Result = DecryptPartly(FileInfo, Buffer, CryptoProvider, FileInfo->DataPercent);

	}
	else if (FileInfo->EncryptMode == HEADER_ENCRYPT) {

		Result = DecryptHeader(FileInfo, Buffer, CryptoProvider);

	}

	LARGE_INTEGER Offset;
	Offset.QuadPart = -534;
	if (SetFilePointerEx(FileInfo->FileHandle, Offset, NULL, FILE_END)) {
		SetEndOfFile(FileInfo->FileHandle);
	}

	if (Result) {

		CloseHandle(FileInfo->FileHandle);
		FileInfo->FileHandle = INVALID_HANDLE_VALUE;
		ChangeFileName(FileInfo->Filename);

	}

	CloseFile(FileInfo);

	return Result;
}


/*
STATIC
DWORD
WINAPI EventHandler(__in LPVOID Args)
{
	HCRYPTKEY RsaKey;
	HCRYPTPROV CryptoProvider;

	LPVOID Buffer = VirtualAlloc(NULL, BufferSize + 32, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!Buffer) {
		ExitThread(EXIT_FAILURE);
	}

	if (!GetCryptoProvider(&CryptoProvider)) {
		return FALSE;
	}

	if (!CryptImportKey(CryptoProvider, g_PrivateKey, sizeof(g_PrivateKey), 0, 0, &RsaKey)) {
		ExitThread(EXIT_FAILURE);
	}

	for (;;)
	{

		DWORD BytesTransferred;
		ULONG_PTR CompletionKey;
		decryptor::LPFILE_INFO FileInfo;

		if (!GetQueuedCompletionStatus(g_IocpHandle, &BytesTransferred, &CompletionKey, (LPOVERLAPPED*)&FileInfo, INFINITE)) {
			ExitThread(EXIT_FAILURE);
		}

		if (CompletionKey == EXIT_COMPLETION_KEY) {
			ExitThread(EXIT_SUCCESS);
		}

		if (Decrypt(FileInfo, (LPBYTE)Buffer, CryptoProvider, RsaKey))
		{

			CloseHandle(FileInfo->FileHandle);
			FileInfo->FileHandle = INVALID_HANDLE_VALUE;
			ChangeFileName(FileInfo->Filename);

		}

		CloseFile(FileInfo);

		memory::Free(FileInfo->Filename);
		GlobalFree(FileInfo);

	}

	VirtualFree(Buffer, 0, MEM_RELEASE);
	CryptDestroyKey(RsaKey);
	ExitThread(EXIT_SUCCESS);
}
*/