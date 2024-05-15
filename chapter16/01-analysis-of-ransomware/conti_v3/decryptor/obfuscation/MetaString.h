#pragma once

#include "metarandom2.h"

#include <array>
#include <utility>

//namespace andrivet { namespace ADVobfuscator {
//} }

#define OBFUSCATE_STRINGS

template <int A, int B>
struct ExtendedEuclidian
{
    enum
    {
        d = ExtendedEuclidian<B, A % B>::d,
        x = ExtendedEuclidian<B, A % B>::y,
        y = ExtendedEuclidian<B, A % B>::x - (A / B) * ExtendedEuclidian<B, A % B>::y
    };
};

template <int A>
struct ExtendedEuclidian<A, 0>
{
    enum
    {
        d = A,
        x = 1,
        y = 0
    };
};

constexpr std::array<int, 30> PrimeNumbers = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113 };

constexpr int positive_modulo(int a, int n)
{
    return (a % n + n) % n;
}

template<unsigned char A, unsigned char B, typename Indexes>
class MetaBuffer;

template<unsigned char A, unsigned char B, size_t... Ints>
class MetaBuffer<A, B, std::index_sequence<Ints...>>
{
public:
    constexpr __forceinline MetaBuffer(const unsigned char* data)
        : m_buffer{ encrypt(data[Ints])... }
    {

    }

    inline bool isDecrypted() const
    {
        return m_isDecrypted;
    }

    inline const char* decrypt()
    {
        if (!isDecrypted())
        {
            for (size_t i = 0; i < sizeof...(Ints); ++i)
                m_buffer[i] = decrypt(m_buffer[i]);
        }

        return (const char*)m_buffer;
    }

private:
    constexpr unsigned char __forceinline encrypt(unsigned char byte) const
    {
        return (A * byte + B) % 127;
    }

    constexpr unsigned char __forceinline decrypt(unsigned char byte) const
    {
        return positive_modulo(ExtendedEuclidian<127, A>::y * (byte - B), 127);
    }

    volatile bool m_isDecrypted = false;
    volatile unsigned char m_buffer[sizeof...(Ints)];
};

// Для ANSI строк.
#define OBFA(str)((const char*)MetaBuffer<std::get<MetaRandom2<__COUNTER__, 30>::value>(PrimeNumbers), \
                  MetaRandom2<__COUNTER__, 126>::value, \
                  std::make_index_sequence<sizeof(str)>>((const unsigned char*)str).decrypt())
// Для UNICODE строк.
#define OBFW(str)((const wchar_t*)MetaBuffer<std::get<MetaRandom2<__COUNTER__, 30>::value>(PrimeNumbers), \
                  MetaRandom2<__COUNTER__, 126>::value, \
                  std::make_index_sequence<sizeof(str)>>((const unsigned char*)str).decrypt())

#if defined(UNICODE) || defined(_UNICODE)
#define _TOBF OBFW
#else
#define _TOBF OBFA
#endif

#ifdef OBFUSCATE_STRINGS
#define _TSTR _TOBF
#define _STR OBFA
#define _WCS OBFW
#else
#define _TSTR(str) str
#define _STR2(str) str
#define _WCS(str) str
#endif // OBFUSCATED_STRINGS