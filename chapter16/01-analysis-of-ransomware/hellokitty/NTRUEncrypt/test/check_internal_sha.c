#include <check.h>

#include "ntru_crypto.h"
#include "ntru_crypto_hmac.h"

#include "test_common.h"
#include "check_common.h"

void
do_hmac_sha256_test(
        size_t key_len, uint8_t const *key,
        size_t data_len, uint8_t const *data,
        size_t test_len, uint8_t const *test)
{
    uint32_t rc;
    uint8_t md[32];
    uint16_t md_len;

    NTRU_CRYPTO_HMAC_CTX *ctx;

    rc = ntru_crypto_hmac_create_ctx(
            NTRU_CRYPTO_HASH_ALGID_SHA256, key, key_len, &ctx);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_OK));

    ntru_crypto_hmac_get_md_len(ctx, &md_len);
    ck_assert_uint_eq(md_len, sizeof(md));

    rc = ntru_crypto_hmac_init(ctx);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_OK));

    rc = ntru_crypto_hmac_update(ctx, data, data_len);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_OK));

    rc = ntru_crypto_hmac_final(ctx, md);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_OK));
    ck_assert_int_eq(memcmp(md, test, test_len), 0);

    rc = ntru_crypto_hmac_destroy_ctx(ctx);
    ck_assert_int_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_OK));
}

START_TEST(test_hmac_sha256_tv1)
{
    uint8_t const key[20] =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"\
        "\x0b\x0b\x0b\x0b";
    uint8_t const data[8] =
        "\x48\x69\x20\x54\x68\x65\x72\x65";
    uint8_t const test[32] =
        "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"\
        "\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";

    do_hmac_sha256_test(
            sizeof(key), key, sizeof(data), data, sizeof(test), test);
}
END_TEST


START_TEST(test_hmac_sha256_tv2)
{
    uint8_t const key[4] =
        "\x4a\x65\x66\x65";
    uint8_t const data[28] =
        "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20"\
        "\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f";
    uint8_t const test[32] =
        "\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7"\
        "\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43";

    do_hmac_sha256_test(
            sizeof(key), key, sizeof(data), data, sizeof(test), test);
}
END_TEST


START_TEST(test_hmac_sha256_tv3)
{
    uint8_t const key[20] =
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa\xaa";
    uint8_t const data[50] =
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"\
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"\
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"\
        "\xdd\xdd";
    uint8_t const test[32] =
        "\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7"\
        "\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe";

    do_hmac_sha256_test(
            sizeof(key), key, sizeof(data), data, sizeof(test), test);
}
END_TEST

START_TEST(test_hmac_sha256_tv4)
{
    uint8_t const key[25] =
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"\
        "\x11\x12\x13\x14\x15\x16\x17\x18\x19";
    uint8_t const data[50] =
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"\
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"\
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"\
        "\xcd\xcd";
    uint8_t const test[32] =
        "\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a"\
        "\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b";

    do_hmac_sha256_test(
            sizeof(key), key, sizeof(data), data, sizeof(test), test);
}
END_TEST


START_TEST(test_hmac_sha256_tv5)
{
    uint8_t const key[20] =
        "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"\
        "\x0c\x0c\x0c\x0c";
    uint8_t const data[20] =
        "\x54\x65\x73\x74\x20\x57\x69\x74\x68\x20\x54\x72\x75\x6e\x63\x61"\
        "\x74\x69\x6f\x6e";
    uint8_t const test[16] =
        "\xa3\xb6\x16\x74\x73\x10\x0e\xe0\x6e\x0c\x79\x6c\x29\x55\x55\x2b";

    do_hmac_sha256_test(
            sizeof(key), key, sizeof(data), data, sizeof(test), test);
}
END_TEST


START_TEST(test_hmac_sha256_tv6)
{
    uint8_t const key[131] =
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
        "\xaa\xaa\xaa";
    uint8_t const data[54] =
        "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"\
        "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"\
        "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"\
        "\x20\x46\x69\x72\x73\x74";
    uint8_t const test[32] =
        "\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f"\
        "\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54";

    do_hmac_sha256_test(
            sizeof(key), key, sizeof(data), data, sizeof(test), test);
}
END_TEST



START_TEST(test_hmac_sha256_tv7)
{
    uint8_t const key[131] =
         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
         "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"\
         "\xaa\xaa\xaa";


    uint8_t const data[152] =
        "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75"\
        "\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68"\
        "\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65"\
        "\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74"\
        "\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64"\
        "\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b\x65\x79\x20\x6e\x65\x65"\
        "\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65\x64\x20"\
        "\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75\x73\x65"\
        "\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c"\
        "\x67\x6f\x72\x69\x74\x68\x6d\x2e";

    uint8_t const test[32] =
        "\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44"\
        "\xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2";

    do_hmac_sha256_test(
            sizeof(key), key, sizeof(data), data, sizeof(test), test);
}
END_TEST


START_TEST(test_hmac)
{
    uint32_t rc;
    uint8_t const key[1] = "a";
    uint8_t md = 0;
    uint16_t md_len;

    NTRU_CRYPTO_HMAC_CTX *ctx;

    /* hmac_init: Null input */
    rc = ntru_crypto_hmac_init(NULL);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_update: Null input */
    rc = ntru_crypto_hmac_update(NULL, key, 1);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    rc = ntru_crypto_hmac_update(ctx, NULL, 1);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_final: Null input */
    rc = ntru_crypto_hmac_final(NULL, &md);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    rc = ntru_crypto_hmac_final(ctx, NULL);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_create_ctx: Context not provided */
    rc = ntru_crypto_hmac_create_ctx(
            NTRU_CRYPTO_HASH_ALGID_SHA256, key, 1, NULL);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_create_ctx: Key not provided */
    rc = ntru_crypto_hmac_create_ctx(
            NTRU_CRYPTO_HASH_ALGID_SHA256, NULL, 1, &ctx);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_create_ctx: Algorithm does not exist */
    rc = ntru_crypto_hmac_create_ctx(-1, key, 1, &ctx);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_ALG));

    /* hmac_get_md_len: Context not provided */
    rc = ntru_crypto_hmac_get_md_len(NULL, &md_len);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_get_md_len: Output pointer not provided */
    rc = ntru_crypto_hmac_get_md_len(ctx, NULL);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_set_key: Context not provided */
    rc = ntru_crypto_hmac_set_key(NULL, (const uint8_t *)"key");
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_set_key: Key not provided */
    rc = ntru_crypto_hmac_get_md_len(ctx, NULL);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));

    /* hmac_destroy_ctx: Context not provided */
    rc = ntru_crypto_hmac_destroy_ctx(NULL);
    ck_assert_uint_eq(rc, HMAC_RESULT(NTRU_CRYPTO_HMAC_BAD_PARAMETER));
}
END_TEST

START_TEST(test_sha1)
{
    uint32_t rc;
    uint32_t i;

    uint16_t blk_len;
    uint16_t md_len;

    NTRU_CRYPTO_HASH_CTX ctx;
    NTRU_CRYPTO_SHA1_CTX sha1ctx;

    uint8_t md[20];
    uint8_t data1[3] = "abc";
    uint8_t data2[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t data3[64] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    uint8_t test1[20] = "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e"\
                        "\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d";
    uint8_t test2[20] = "\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae"\
                        "\x4a\xa1\xf9\x51\x29\xe5\xe5\x46\x70\xf1";
    uint8_t test3[20] = "\x34\xaa\x97\x3c\xd4\xc4\xda\xa4\xf6\x1e"\
                        "\xeb\x2b\xdb\xad\x27\x31\x65\x34\x01\x6f";

    rc = ntru_crypto_hash_digest(
            NTRU_CRYPTO_HASH_ALGID_SHA1, data1, sizeof(data1), md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));
    ck_assert_int_eq(memcmp(md, test1, 20), 0);

    rc = ntru_crypto_hash_digest(
            NTRU_CRYPTO_HASH_ALGID_SHA1, data2, sizeof(data2), md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));
    ck_assert_int_eq(memcmp(md, test2, 20), 0);

    rc = ntru_crypto_hash_set_alg(NTRU_CRYPTO_HASH_ALGID_SHA1, &ctx);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_OK));

    rc = ntru_crypto_hash_block_length(&ctx, &blk_len);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_OK));
    ck_assert_uint_eq(blk_len, 64);

    rc = ntru_crypto_hash_digest_length(&ctx, &md_len);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_OK));
    ck_assert_uint_eq(md_len, 20);

    rc = ntru_crypto_hash_init(&ctx);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));

    for(i=0; i < 15625; i++)
    {
        rc = ntru_crypto_hash_update(&ctx, data3, sizeof(data3));
        ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));
    }

    rc = ntru_crypto_hash_final(&ctx, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));

    ck_assert_int_eq(memcmp(md, test3, 20), 0);

    /* Test error cases */

    /* sha1: Context not provided */
    rc = ntru_crypto_sha1(NULL, NULL, data1, sizeof(data1), SHA_INIT, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha1: Input not not provided */
    rc = ntru_crypto_sha1(&sha1ctx, NULL, NULL, sizeof(data1), SHA_INIT, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha1: Digest not provided */
    rc = ntru_crypto_sha1(
            &sha1ctx, NULL, data1, sizeof(data1), SHA_FINISH, NULL);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha1: Alternate initialization (not allowed, should fail) */
    uint32_t init[4] = {0, 0, 0, 0};
    rc = ntru_crypto_sha1(
            &sha1ctx, init, data1, sizeof(data1), SHA_INIT, NULL);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha1: Try to update a ctx with > 63 bytes in its unhashed data buffer */
    sha1ctx.unhashed_len = 64;
    rc = ntru_crypto_sha1(
            &sha1ctx, init, data1, sizeof(data1), 0, NULL);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_FAIL));

    /* Test overflow */
    rc = ntru_crypto_hash_init(&ctx);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));

    ctx.alg_ctx.sha1.num_bits_hashed[0] = 0xffffffff;
    ctx.alg_ctx.sha1.num_bits_hashed[1] = 0xffffffff;
    rc = ntru_crypto_hash_update(&ctx, data3, sizeof(data3));
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OVERFLOW));

    rc = ntru_crypto_hash_final(&ctx, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));
}
END_TEST


START_TEST(test_sha256)
{
    uint32_t rc;
    uint32_t i;

    uint16_t blk_len;
    uint16_t md_len;

    NTRU_CRYPTO_HASH_CTX ctx;
    NTRU_CRYPTO_SHA2_CTX sha2ctx;

    uint8_t md[20];
    uint8_t data1[3] = "abc";
    uint8_t data2[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t data3[64] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    uint8_t test1[32] =
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"\
        "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad";
    uint8_t test2[32] =
        "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"\
        "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1";
    uint8_t test3[32] =
        "\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67"\
        "\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0";

    rc = ntru_crypto_hash_digest(
            NTRU_CRYPTO_HASH_ALGID_SHA256, data1, sizeof(data1), md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));
    ck_assert_int_eq(memcmp(md, test1, sizeof(test1)), 0);

    rc = ntru_crypto_hash_digest(
            NTRU_CRYPTO_HASH_ALGID_SHA256, data2, sizeof(data2), md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));
    ck_assert_int_eq(memcmp(md, test2, sizeof(test2)), 0);

    rc = ntru_crypto_hash_set_alg(NTRU_CRYPTO_HASH_ALGID_SHA256, &ctx);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_OK));

    rc = ntru_crypto_hash_block_length(&ctx, &blk_len);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_OK));
    ck_assert_uint_eq(blk_len, 64);

    rc = ntru_crypto_hash_digest_length(&ctx, &md_len);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_OK));
    ck_assert_uint_eq(md_len, 32);

    rc = ntru_crypto_hash_init(&ctx);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));

    /* Hash "a" repeated 64*15625 = 1000000 times */
    for(i=0; i < 15625; i++)
    {
        rc = ntru_crypto_hash_update(&ctx, data3, sizeof(data3));
        ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));
    }

    rc = ntru_crypto_hash_final(&ctx, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));

    ck_assert_int_eq(memcmp(md, test3, sizeof(test3)), 0);

    /* Test error cases */

    /* sha2: Algorithm other than SHA256 */
    rc = ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA1, &sha2ctx,
            NULL, data1, sizeof(data1), SHA_INIT, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha2: Context not provided */
    rc = ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, NULL,
            NULL, data1, sizeof(data1), SHA_INIT, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha2: Input not not provided */
    rc = ntru_crypto_sha2(NTRU_CRYPTO_HASH_ALGID_SHA256, &sha2ctx,
            NULL, NULL, sizeof(data1), SHA_INIT, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha2: Digest not provided */
    rc = ntru_crypto_sha2(
            NTRU_CRYPTO_HASH_ALGID_SHA256, &sha2ctx,
            NULL, data1, sizeof(data1), SHA_FINISH, NULL);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha2: Alternate initialization (not allowed, should fail) */
    uint32_t init[4] = {0, 0, 0, 0};
    rc = ntru_crypto_sha2(
            NTRU_CRYPTO_HASH_ALGID_SHA256, &sha2ctx,
            init, data1, sizeof(data1), SHA_INIT, NULL);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_BAD_PARAMETER));

    /* sha2: Try to update a ctx with > 63 bytes in its unhashed data buffer */
    sha2ctx.unhashed_len = 64;
    rc = ntru_crypto_sha2(
            NTRU_CRYPTO_HASH_ALGID_SHA256, &sha2ctx,
            init, data1, sizeof(data1), 0, NULL);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_FAIL));

    /* Test overflow */
    rc = ntru_crypto_hash_init(&ctx);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));

    ctx.alg_ctx.sha256.num_bits_hashed[0] = 0xffffffff;
    ctx.alg_ctx.sha256.num_bits_hashed[1] = 0xffffffff;
    rc = ntru_crypto_hash_update(&ctx, data3, sizeof(data3));
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OVERFLOW));

    rc = ntru_crypto_hash_final(&ctx, md);
    ck_assert_uint_eq(rc, SHA_RESULT(SHA_OK));
}
END_TEST

START_TEST(test_hash)
{
    uint32_t rc;

    NTRU_CRYPTO_HASH_CTX ctx;
    uint16_t blen;
    uint16_t dlen;

    uint8_t const data[1] = "a";
    uint8_t md[32];

    /* Context not provided */
    rc = ntru_crypto_hash_set_alg(NTRU_CRYPTO_HASH_ALGID_SHA256, NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* Algorithm doesn't exist */
    rc = ntru_crypto_hash_set_alg(-1, &ctx);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* block_length: Context not provided */
    rc = ntru_crypto_hash_block_length(NULL, &blen);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* block_length: Result pointer not provided */
    rc = ntru_crypto_hash_block_length(&ctx, NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* block_length: A call to set_alg hasn't succeeded */
    rc = ntru_crypto_hash_block_length(&ctx, &blen);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* digest_length: Context not provided */
    rc = ntru_crypto_hash_digest_length(NULL, &dlen);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* digest_length: result pointer not provided */
    rc = ntru_crypto_hash_digest_length(&ctx, NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* digest_length: A call to set_alg hasn't succeeded */
    rc = ntru_crypto_hash_digest_length(&ctx, &dlen);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* init: Context not provided */
    rc = ntru_crypto_hash_init(NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* init: A call to set_alg hasn't succeeded */
    rc = ntru_crypto_hash_init(&ctx);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* update: Context not provided */
    rc = ntru_crypto_hash_update(NULL, data, 1);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* update: Data not provided, non-zero length */
    rc = ntru_crypto_hash_update(&ctx, NULL, 1);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* update: A call to set_alg hasn't succeeded */
    rc = ntru_crypto_hash_update(&ctx, data, 1);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* final: Context not provided */
    rc = ntru_crypto_hash_final(NULL, md);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* final: Digest buffer not provided */
    rc = ntru_crypto_hash_final(&ctx, NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* final: A call to set_alg hasn't succeeded */
    rc = ntru_crypto_hash_final(&ctx, md);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* digest: Algorithm doesn't exist */
    rc = ntru_crypto_hash_digest(-1, data, 1, md);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_ALG));

    /* digest: Data not provided, non-zero length */
    rc = ntru_crypto_hash_digest(NTRU_CRYPTO_HASH_ALGID_SHA256, NULL, 1, md);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

    /* digest: output buffer not provided*/
    rc = ntru_crypto_hash_digest(NTRU_CRYPTO_HASH_ALGID_SHA256, data, 1, NULL);
    ck_assert_uint_eq(rc, HASH_RESULT(NTRU_CRYPTO_HASH_BAD_PARAMETER));

}
END_TEST

Suite *
ntruencrypt_internal_sha_suite(void)
{
    Suite *s;
    TCase *tc_sha;

    s = suite_create("NTRUEncrypt.Internal.SHA");

    tc_sha = tcase_create("SHA");
    suite_add_tcase(s, tc_sha);

    /* Test HMAC SHA256 vectors from https://www.ietf.org/rfc/rfc4231.txt */
    tcase_add_test(tc_sha, test_hmac);
    tcase_add_test(tc_sha, test_hmac_sha256_tv1);
    tcase_add_test(tc_sha, test_hmac_sha256_tv2);
    tcase_add_test(tc_sha, test_hmac_sha256_tv3);
    tcase_add_test(tc_sha, test_hmac_sha256_tv4);
    tcase_add_test(tc_sha, test_hmac_sha256_tv5);
    tcase_add_test(tc_sha, test_hmac_sha256_tv6);
    tcase_add_test(tc_sha, test_hmac_sha256_tv7);
    tcase_add_test(tc_sha, test_hash);
    tcase_add_test(tc_sha, test_sha1);
    tcase_add_test(tc_sha, test_sha256);

    return s;
}
