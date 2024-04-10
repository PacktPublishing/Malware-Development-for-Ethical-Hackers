#include <windows.h>


#include <ntru_crypto.h>

#include "randomMbedTls.hpp"


typedef struct _entropy_info {
	size_t index;
	uint8_t* buffer;
	size_t size;
} entropy_info;


const int minBytesOfEntropy = (256 * 2) / 8;


static uint8_t get_entropy(ENTROPY_CMD cmd, uint8_t* out, void* lparam)
{
	auto eInfo = (entropy_info*)lparam;

	if (cmd == INIT) {
		/* Any initialization for a real entropy source goes here. */
		eInfo->index = 0;
		return 1;
	}

	if (out == NULL)
		return 0;

	if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
		/* Here we return the number of bytes needed from the entropy
		 * source to obtain 8 bits of entropy.  Maximum is 8.
		 */
		*out = 1;                       /* this is a perfectly random source */
		return 1;
	}

	if (cmd == GET_BYTE_OF_ENTROPY) {
		*out = eInfo->buffer[eInfo->index++];
		return 1;
	}
	return 0;
}


class NTrueDrbg {
public:
	NTrueDrbg() 
	{
		InitializeCriticalSection(&cs);

		RandomMBedTls random;
		entropy_info* eInfo = new entropy_info();
		eInfo->size = minBytesOfEntropy;
		eInfo->buffer = (uint8_t*)malloc(eInfo->size);

		random.getRandomBytes(eInfo->buffer, eInfo->size);

		uint32_t rc = ntru_crypto_drbg_instantiate(256, nullptr, 0, (ENTROPY_FN)&get_entropy, &drbg, eInfo);

		free(eInfo->buffer);
		delete eInfo;
	}

	DRBG_HANDLE getHandle() {
		return drbg;
	}

	void SyncEnter() {
		EnterCriticalSection(&cs);
	}

	void SyncLeave() {
		LeaveCriticalSection(&cs);
	}

	virtual ~NTrueDrbg() {
		uint32_t rc = ntru_crypto_drbg_uninstantiate(drbg);
		DeleteCriticalSection(&cs);
	}
private:
	DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
	CRITICAL_SECTION cs;
};


class NTRUEncrypt256 {
public:
	NTRUEncrypt256() {

		public_key = nullptr;
		public_key_len = 0;
		private_key = nullptr;
		private_key_len = 0;
	}

	virtual ~NTRUEncrypt256() {
		if (public_key) {
			SecureZeroMemory(public_key, public_key_len);
			free(public_key);
		}
		if (private_key) {
			SecureZeroMemory(private_key, private_key_len);
			free(private_key);
		}
	}

	/*
	call with ciphertext = nullptr
	to get ciphertext_len of needed buffer
	*/
	bool Encrypt(NTrueDrbg* ntruDrbg, uint8_t* dataToEncrypt, uint16_t dataToEncryptSize, uint8_t* ciphertext, uint16_t *ciphertext_len)
	{
		if (public_key_len == 0)
			return false;

		ntruDrbg->SyncEnter();
		uint32_t rc = ntru_crypto_ntru_encrypt(ntruDrbg->getHandle(), public_key_len, public_key, dataToEncryptSize, dataToEncrypt, ciphertext_len, ciphertext);
		ntruDrbg->SyncLeave();

		if (rc != 0) {
			// dbg(LEVEL1, "ntru_crypto_ntru_encrypt %x", rc);
		}

		return (rc == 0);
	}

	bool Decrypt(uint8_t* ciphertext, uint16_t ciphertext_len, uint8_t* plaintext, uint16_t* plaintext_len) {
		if (private_key_len == 0)
			return false;

		uint32_t rc = ntru_crypto_ntru_decrypt(private_key_len, private_key, ciphertext_len, ciphertext, plaintext_len, plaintext);
		return (rc == 0);
	}

	bool GenKeys(NTrueDrbg* ntruDrbg)
	{
		uint32_t rc = ntru_crypto_ntru_encrypt_keygen(ntruDrbg->getHandle(), NTRU_EES743EP1, &public_key_len, NULL, &private_key_len, NULL);
		if (rc == 0) 
		{
			free(public_key);
			free(private_key);

			public_key = (uint8_t*)malloc(public_key_len);          /* sized for NTRU_EES743EP1 */
			private_key = (uint8_t*)malloc(private_key_len);         /* sized for NTRU_EES743EP1 */

			ntruDrbg->SyncEnter();
			rc = ntru_crypto_ntru_encrypt_keygen(ntruDrbg->getHandle(), NTRU_EES743EP1, &public_key_len, public_key, &private_key_len, private_key);
			ntruDrbg->SyncLeave();

			return (rc == NTRU_OK);
		}

		return false;
	}

	uint8_t* GetPrivatePtr() {
		return private_key;
	}

	uint8_t *GetPublicPtr() {
		return public_key;
	}

	uint16_t GetPublicLen() {
		return public_key_len;
	}

	uint16_t GetPrivateLen() {
		return private_key_len;
	}

	void SetPrivateKey(uint8_t* key, uint16_t size) {
		if (!size)
			return;

		free(private_key);

		private_key = 0;
		private_key_len = 0;

		if (private_key = (uint8_t*)malloc(size)) {
			private_key_len = size;
			memcpy(private_key, key, size);
		}
	}

	void SetPublicKey(uint8_t* key, uint16_t size) {
		if (!size)
			return;

		free(public_key);

		public_key = 0;
		public_key_len = 0;

		if (public_key = (uint8_t*)malloc(size)) {
			public_key_len = size;
			memcpy(public_key, key, size);
		}
	}

private: 
	uint8_t* public_key;
	uint8_t* private_key;
	uint16_t public_key_len;          /* no. of octets in public key */
	uint16_t private_key_len;         /* no. of octets in private key */
};