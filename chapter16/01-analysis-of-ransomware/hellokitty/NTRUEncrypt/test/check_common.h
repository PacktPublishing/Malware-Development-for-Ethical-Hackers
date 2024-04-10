#ifndef NTRU_CHECK_COMMON_H
#define NTRU_CHECK_COMMON_H

DRBG_HANDLE drbg;

/* Common components for tests that depend on CHECK library */

void test_drbg_setup(void);
void test_drbg_teardown(void);

typedef struct _NTRU_CK_MEM {
    uint8_t   *_alloc;
    uint8_t   *ptr;
    size_t     len;
} NTRU_CK_MEM;

uint8_t * ntru_ck_malloc(NTRU_CK_MEM *obj, size_t size);
void ntru_ck_mem_ok(NTRU_CK_MEM *obj);
void ntru_ck_mem_free(NTRU_CK_MEM *obj);

Suite * ntruencrypt_internal_poly_suite(void);
Suite * ntruencrypt_internal_key_suite(void);
Suite * ntruencrypt_internal_sha_suite(void);
Suite * ntruencrypt_internal_mgf_suite(void);

#endif
