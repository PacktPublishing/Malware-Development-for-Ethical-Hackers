#include "hash.h"
#include "..\memory.h"

#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }
#define LowerChar(C) if (C >= 'A' && C <= 'Z') {C = C + ('a'-'A');}

unsigned int MurmurHash2A(const void* key, int len, unsigned int seed)
{
	char temp[64];
	RtlSecureZeroMemory(temp, 64);
	memory::Copy(temp, (PVOID)key, len);

	for (int i = 0; i < len; i++) {
		LowerChar(temp[i]);
	}

	const unsigned int m = 0x5bd1e995;
	const int r = 24;
	unsigned int l = len;

	const unsigned char* data = (const unsigned char*)temp;

	unsigned int h = seed;
	unsigned int k;

	while (len >= 4)
	{
		k = *(unsigned int*)data;

		mmix(h, k);

		data += 4;
		len -= 4;
	}

	unsigned int t = 0;

	switch (len)
	{
	case 3: t ^= data[2] << 16;
	case 2: t ^= data[1] << 8;
	case 1: t ^= data[0];
	};

	mmix(h, t);
	mmix(h, l);

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}