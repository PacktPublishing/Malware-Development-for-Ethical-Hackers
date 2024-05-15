#pragma once

#ifdef __cplusplus
//#include "../include/targetver.h"
#include "obfuscation/MetaRandom2.h"
#endif

//
// ����������� ��� �������� ���� ������������� (����� ���� � ��� �� ����� ���� ��� ����������
// ���������� ������ ������������������ ����������, � ������ ���� �������� ��������� ������� ����).
// ������������ ���:
//
// foo();            // ���-�� ��������
// 
// morphcode();      // ����������� ������� 
//
// int a = bar();    // ���-�� ��������
//
// morphcode(a);     // ����������� �������, ������������ ���������� ����������� ��������
//



#if defined(MORPHCODE)

#define morphcode()
#define morphcode(a)

#else



// ����������� ��������� ������� � ���, ��� ������������ ��������
#ifdef __cplusplus
__forceinline void morphcode(int a) {
#else
__forceinline void morphcode(char* a) {
#endif
#ifdef __cplusplus
	volatile int _morph_var = static_cast<int>(1 + MetaRandom2<0, 0x7FFFFF - 1>::value);
#else
	volatile int _morph_var = a;
#endif

	// ������ �������������� �������� �� ��������� (������� ����������) ������, � ���������.
	// �� ���� ����, ��� ����� �������� �� ����� ����������, ����������� ������� ���� ���� ������� ��������,
	// ������� ���������. ����� �������, ���� � �� �� ������� ����� ������ ������ ��� ������ ���������.
	if (_morph_var % 3) {
		_morph_var += (int)a + 2;
		while (!(_morph_var % 4)) ++_morph_var;
	}
	else if (_morph_var % 2) {
		_morph_var -= (int)a - 2;
		while (!(_morph_var % 3)) ++_morph_var;
	}
	else if (_morph_var % 4) {
		_morph_var = (_morph_var + 2) * ((int)a + 3);
		while (!(_morph_var % 2))
			if (_morph_var % 5)
				--_morph_var;
			else ++_morph_var;
	}
	else if (_morph_var % 5) {
		_morph_var = (_morph_var + 11) / ((int)a + 23);
		while (!(_morph_var % 3))
			if (_morph_var % 5)
				++_morph_var;
			else --_morph_var;
	}
}

// ����������� ��������� ������� � ���, ��� ������������ ��������
#ifdef __cplusplus
__forceinline void morphcode(void* a) {
	morphcode((int)a);
}
#endif

// ����������� ��������� ������� � ���, ��� ������������ ��������
#ifdef __cplusplus
__forceinline void morphcode(void) {
	// ������������ ���������� �����

	volatile int _morph_var = static_cast<int>(1 + MetaRandom2<0, 0x7FFFFF - 1>::value);
}
#endif

#endif