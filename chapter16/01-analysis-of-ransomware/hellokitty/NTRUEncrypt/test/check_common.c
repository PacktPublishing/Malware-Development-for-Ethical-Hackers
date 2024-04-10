#include <check.h>

#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"

#include "test_common.h"
#include "check_common.h"

void
test_drbg_setup(void)
{
    uint32_t rc;
    rc = ntru_crypto_drbg_external_instantiate(
                                    (RANDOM_BYTES_FN) &randombytes, &drbg);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));
}

void
test_drbg_teardown(void)
{
    uint32_t rc;
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));
}

uint8_t *
ntru_ck_malloc(NTRU_CK_MEM *obj, size_t size)
{
    uint32_t i;
    obj->_alloc = (uint8_t *)malloc(size+32);
    ck_assert_ptr_ne(obj->_alloc, NULL);
    /* Fill first 16 bytes with random data */
    randombytes(obj->_alloc, 16);
    /* Fill last 16 bytes with bit-wise negation of first 16 */
    for(i=0; i<16; i++)
    {
        obj->_alloc[16+size+i] = ~(obj->_alloc[i]);
    }
    obj->ptr = obj->_alloc+16;
    obj->len = size;

    return obj->ptr;
}

void
ntru_ck_mem_ok(NTRU_CK_MEM *obj)
{
    uint32_t i;
    uint8_t r=0;
    /* check that xor of first 16 bytes with last 16 bytes gives all 1s */
    for(i=0; i<16; i++)
    {
        r |= (obj->_alloc[i] ^ obj->_alloc[16 + obj->len + i]) + 1;
    }
    ck_assert_uint_eq(r, 0);
}

void
ntru_ck_mem_free(NTRU_CK_MEM *obj)
{
    free(obj->_alloc);
    obj->ptr = NULL;
    obj->len = 0;
}
