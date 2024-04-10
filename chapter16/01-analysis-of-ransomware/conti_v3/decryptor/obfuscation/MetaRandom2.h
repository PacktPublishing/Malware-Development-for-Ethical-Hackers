#ifndef META_RANDOM_H
#define META_RANDOM_H

#include <limits>

//namespace andrivet { namespace ADVobfuscator {
//} }


constexpr int RandomSeed(void)
{
    return '0' * -40271 + // offset accounting for digits' ANSI offsets
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

template <unsigned int a, unsigned int c, unsigned int seed, unsigned int Limit>
struct LinearCongruentialEngine
{
    enum
    {
        value = (a * LinearCongruentialEngine<a, c - 1, seed, Limit>::value + c) % Limit
    };
};

template <unsigned int a, unsigned int seed, unsigned int Limit>
struct LinearCongruentialEngine<a, 0, seed, Limit>
{
    enum
    {
        value = (a * seed) % Limit
    };
};

template <int N, int Limit>
struct MetaRandom2
{
    enum
    {
        value = LinearCongruentialEngine<16807, N, RandomSeed(), Limit>::value
    };
};

#endif // META_RANDOM_H