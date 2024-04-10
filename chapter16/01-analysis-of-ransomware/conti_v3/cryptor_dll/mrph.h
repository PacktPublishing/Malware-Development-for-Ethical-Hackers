#pragma once

#ifdef __cplusplus
//#include "../include/targetver.h"
#include "obfuscation/MetaRandom2.h"
#endif

//
// »нструменты дл€ придани€ коду полиморфности (чтобы один и тот же кусок кода при компил€ции
// производил разные последовательности инструкций, и нельз€ было выделить сигнатуру участка кода).
// »спользовать так:
//
// foo();            // что-то полезное
// 
// morphcode();      // полиморфна€ вставка 
//
// int a = bar();    // что-то полезное
//
// morphcode(a);     // полиморфна€ вставка, использующа€ результаты предыдущего действи€
//



#if defined(MORPHCODE)

#define morphcode()
#define morphcode(a)

#else



// полиморфна€ рандомна€ вставка в код, дл€ рандомизации сигнатур
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

	// делаем арифметическую операцию со случайным (времени компил€ции) числом, и операндом.
	// за счет того, что число известно во врем€ компил€ции, оптимизатор оставит лишь один вариант действи€,
	// выкинув остальные. “аким образом, одна и та же вставка будет давать вс€кий раз разный результат.
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

// полиморфна€ рандомна€ вставка в код, дл€ рандомизации сигнатур
#ifdef __cplusplus
__forceinline void morphcode(void* a) {
	morphcode((int)a);
}
#endif

// полиморфна€ рандомна€ вставка в код, дл€ рандомизации сигнатур
#ifdef __cplusplus
__forceinline void morphcode(void) {
	// присваивание случайного числа

	volatile int _morph_var = static_cast<int>(1 + MetaRandom2<0, 0x7FFFFF - 1>::value);
}
#endif

#endif