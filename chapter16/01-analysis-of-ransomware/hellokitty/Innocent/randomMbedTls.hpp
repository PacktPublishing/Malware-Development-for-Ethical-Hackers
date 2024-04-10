#pragma once

#include <windows.h>



#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"



class RandomMBedTls {
public:
	RandomMBedTls() 
	{
	//	char cName[MAX_COMPUTERNAME_LENGTH+1];
	//	DWORD dwSize = sizeof(cName);
	//	GetComputerNameA(cName, &dwSize);

		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_init(&ctr_drbg);

		int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
		//	(const unsigned char*)cName, lstrlenA(cName)
			0,0
		);

		initialized = (ret == 0);
	}

	void getRandomBytes(unsigned char* ptr, size_t size) {
		mbedtls_ctr_drbg_random(&ctr_drbg, ptr, size);
	}

	virtual ~RandomMBedTls() {
		//mbedtls_entropy_free(&entropy);
		//mbedtls_ctr_drbg_free(&ctr_drbg);
	}
private:
	bool initialized;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
};