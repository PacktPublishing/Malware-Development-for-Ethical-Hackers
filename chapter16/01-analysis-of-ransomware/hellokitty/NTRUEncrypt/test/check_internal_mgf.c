#include <check.h>

#include "ntru_crypto.h"
#include "ntru_crypto_sha256.h"
#include "ntru_crypto_ntru_mgf1.h"

#include "test_common.h"
#include "check_common.h"

START_TEST(test_mgf)
{
    uint32_t rc;

    NTRU_CK_MEM state_mem;
    NTRU_CK_MEM seed_mem;
    NTRU_CK_MEM out1_mem;
    NTRU_CK_MEM out2_mem;

    uint8_t *state;
    uint8_t *seed;
    uint8_t *out1;
    uint8_t *out2;

    state = ntru_ck_malloc(&state_mem, SHA_256_MD_LEN + 4);
    seed = ntru_ck_malloc(&seed_mem, SHA_256_MD_LEN + 8);
    out1 = ntru_ck_malloc(&out1_mem, 10*SHA_256_MD_LEN);
    out2 = ntru_ck_malloc(&out2_mem, 10*SHA_256_MD_LEN);

    randombytes(seed, state_mem.len);

    /* Check reproducibility */
    /* seed */
    rc = ntru_mgf1(state, NTRU_CRYPTO_HASH_ALGID_SHA256, SHA_256_MD_LEN,
            0, seed_mem.len, seed, NULL);
    /* make 10 calls */
    rc = ntru_mgf1(state, NTRU_CRYPTO_HASH_ALGID_SHA256, SHA_256_MD_LEN,
            10, 0, NULL, out1);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* reseed with same seed */
    rc = ntru_mgf1(state, NTRU_CRYPTO_HASH_ALGID_SHA256, SHA_256_MD_LEN,
            0, seed_mem.len, seed, NULL);
    rc = ntru_mgf1(state, NTRU_CRYPTO_HASH_ALGID_SHA256, SHA_256_MD_LEN,
            10, 0, NULL, out2);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* compare outputs (should match) */
    ck_assert_int_eq(memcmp(out1, out2, out1_mem.len), 0);

    /* Check dependence on counter */
    /* reseed with same seed */
    rc = ntru_mgf1(state, NTRU_CRYPTO_HASH_ALGID_SHA256, SHA_256_MD_LEN,
            0, seed_mem.len, seed, NULL);
    /* change counter */
    memset(state + SHA_256_MD_LEN, 0xff, 4);
    /* make 10 calls */
    rc = ntru_mgf1(state, NTRU_CRYPTO_HASH_ALGID_SHA256, SHA_256_MD_LEN,
            10, 0, NULL, out2);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* compare outputs (should not match) */
    ck_assert_int_ne(memcmp(out1, out2, out1_mem.len), 0);

    /* Try an unknown algorithm */
    rc = ntru_mgf1(state, -1, SHA_256_MD_LEN, 1, 0, NULL, out1);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    ntru_ck_mem_ok(&state_mem);
    ntru_ck_mem_ok(&seed_mem);
    ntru_ck_mem_ok(&out1_mem);
    ntru_ck_mem_ok(&out2_mem);

    ntru_ck_mem_free(&state_mem);
    ntru_ck_mem_free(&seed_mem);
    ntru_ck_mem_free(&out2_mem);
}
END_TEST

START_TEST(test_mgftp1)
{
    uint32_t rc;

    /* Check error cases */
    /* Fail in mgf1, initial request */
    rc = ntru_mgftp1(-1,SHA_256_MD_LEN, 1, 0, NULL, NULL, 5, NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* Fail in mgf1, num_trits_needed >= 5 */
    rc = ntru_mgftp1(-1,SHA_256_MD_LEN, 0, 0, NULL, NULL, 5, NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* Fail in mgf1, num_trits_needed < 5 */
    rc = ntru_mgftp1(-1,SHA_256_MD_LEN, 0, 0, NULL, NULL, 1, NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));
}
END_TEST

Suite *
ntruencrypt_internal_mgf_suite(void)
{
    Suite *s;
    TCase *tc_mgf;

    s = suite_create("NTRUEncrypt.Internal.MGF");

    tc_mgf = tcase_create("Key");
    tcase_add_test(tc_mgf, test_mgf);
    tcase_add_test(tc_mgf, test_mgftp1);

    suite_add_tcase(s, tc_mgf);

    return s;
}

