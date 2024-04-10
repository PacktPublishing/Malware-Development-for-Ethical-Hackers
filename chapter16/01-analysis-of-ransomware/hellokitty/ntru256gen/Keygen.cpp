#include <stdio.h>
#include <string.h>

#include "..\enc-struct.h"
#include "..\sha256\sha256.h"

#include "..\Innocent\ntru.hpp"
#include "ntru_crypto.h"


void print_buf(FILE* file, const char *title, const unsigned char *buf, size_t buf_len)
{
	size_t i = 0;
	fprintf(file, "#pragma once\n\n// size = %d\n\n  uint8_t %s[%d] = { ", buf_len, title, buf_len);
	for (i = 0; i < buf_len - 1; ++i)
		fprintf(file, "0x%02X%s", buf[i], ", ");

	fprintf(file, "0x%02X%s", buf[buf_len - 1], " };\n");
}


void print_buf_js(
	FILE* file, 
	uint8_t* pubkey,
	uint16_t pubkeylen,
	uint8_t* privkey,
	uint16_t privkeylen
)
{
	fprintf(file, "// public\n%d\n", pubkeylen);
	for (int i = 0; i < pubkeylen - 1; ++i)
		fprintf(file, "%02X%s", pubkey[i], "");
	fprintf(file, "%02X%s", pubkey[pubkeylen- 1], "\n");

	fprintf(file, "// private\n%d\n", privkeylen);
	for (int i = 0; i < privkeylen - 1; ++i)
		fprintf(file, "%02X%s", privkey[i], "");
	fprintf(file, "%02X%s", privkey[privkeylen - 1], "\n");
}



void GetHex(uint8_t* bytes, size_t size, char* output)
{
	char singleHex[32];
	output[0] = 0;

	for (size_t i = 0; i != size; i++)
	{
		wsprintfA(singleHex, "%02x", bytes[i] & 0xFF);
		lstrcatA(output, singleHex);
	}
}


int main() 
{

	for (int i = 0; i < 1000; i++) 
	{
		FILE* f;
		char filename[1024];
		NTRUEncrypt256 enc;
		NTrueDrbg drbg;

		if (enc.GenKeys(&drbg)) 
		{
			BYTE sha256[SHA256_BLOCK_SIZE] = { 0 };
			sha256_hash((char*)enc.GetPublicPtr(), enc.GetPublicLen(), sha256);

			char chatName[256];
			GetHex(sha256, sizeof(sha256), chatName);

			sprintf_s(filename, "%s.ntru.pub.priv.txt", chatName);
			fopen_s(&f, filename, "w+");
			if (f != NULL)
			{
				print_buf_js(f,
					enc.GetPublicPtr(), enc.GetPublicLen(),
					enc.GetPrivatePtr(), enc.GetPrivateLen()
				);
				fclose(f);
			}
		}

	}

	return 0;
}