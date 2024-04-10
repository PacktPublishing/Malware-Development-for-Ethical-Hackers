#pragma once



#include "mbedtls/aes.h"
#include "randomMbedTls.hpp"

#include "..\enc-struct.h"



class AES128MbedTls {
public:
	AES128MbedTls() {
		memset(&aes, 0, sizeof(aes));
		memset(iv, 0, sizeof(iv));
		memset(key, 0, sizeof(key));
	}
	virtual ~AES128MbedTls() {
		memset(key, 0, sizeof(key));
		memset(iv, 0, sizeof(iv));
	}
	void GenKeyIv(int _mode) 
	{
		random.getRandomBytes(key, AES_BLOCKLEN);
		random.getRandomBytes(iv, 16);

		/*
		AES_init_ctx_iv(&aes_ctx, key, iv);
		*/
		
		if (_mode == MBEDTLS_AES_ENCRYPT)
			mbedtls_aes_setkey_enc(&aes, key, AES_BLOCKLEN * 8);
		else
			mbedtls_aes_setkey_dec(&aes, key, AES_BLOCKLEN * 8);
		
	}
	// length must be multiply of AES_BLOCKLEN
	bool Encrypt(unsigned char* inbuff, unsigned char* output, size_t length) {
		//AES_CBC_encrypt_buffer(&aes_ctx, inbuff, length / AES_BLOCKLEN);
		//return true;
		bool res = (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, inbuff, output) == 0);

		return res;
	}

	bool Decrypt(unsigned char* inbuff, unsigned char* output, size_t length) {
		//AES_CBC_decrypt_buffer(&aes_ctx, inbuff, length / AES_BLOCKLEN);
		//return true;
		return (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iv, inbuff, output) == 0);
	}

	void CopyKeyIv(unsigned char* _key, unsigned char* _iv) {
		memcpy(_key, key, sizeof(key));
		memcpy(_iv, iv, sizeof(iv));
	}


	// MBEDTLS_AES_ENCRYPT
	// MBEDTLS_AES_DECRYPT
	void SetKeyIv(unsigned char* _key, unsigned char* _iv, int _mode) {

		//AES_init_ctx_iv(&aes_ctx, _key, _iv);

		memcpy(iv, _iv, AES_BLOCKLEN);
		memcpy(key, _key, AES_BLOCKLEN);
		if (_mode == MBEDTLS_AES_ENCRYPT)
			mbedtls_aes_setkey_enc(&aes, key, AES_BLOCKLEN * 8);
		else
			mbedtls_aes_setkey_dec(&aes, key, AES_BLOCKLEN * 8);
	}

	int GetKeySizeInBytes() {
		return sizeof(key);
	}
private:
	RandomMBedTls random;
	mbedtls_aes_context aes;
	unsigned char key[AES_BLOCKLEN];
	unsigned char iv[16];
//	AES_ctx aes_ctx;
	//
};