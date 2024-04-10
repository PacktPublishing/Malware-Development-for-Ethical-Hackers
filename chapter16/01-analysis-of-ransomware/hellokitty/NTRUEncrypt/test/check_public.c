#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"
#include "test_common.h"
#include "check_common.h"


START_TEST(test_api_crypto)
{
    uint32_t rc;


    NTRU_CK_MEM public_key_mem;
    NTRU_CK_MEM public_key2_mem;
    NTRU_CK_MEM private_key_mem;
    NTRU_CK_MEM message_mem;
    NTRU_CK_MEM ciphertext_mem;
    NTRU_CK_MEM plaintext_mem;
    NTRU_CK_MEM encoded_public_key_mem;

    uint8_t *public_key = NULL;
    uint8_t *public_key2 = NULL;
    uint8_t *private_key = NULL;
    uint8_t *message = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *plaintext = NULL;
    uint8_t *encoded_public_key = NULL;
    uint8_t *next = NULL;

    uint8_t tag = 0;

    uint16_t max_msg_len = 0;
    uint16_t mlen = 0;
    uint16_t public_key_len = 0;
    uint16_t public_key2_len = 0;
    uint16_t private_key_len = 0;
    uint16_t ciphertext_len = 0;
    uint16_t plaintext_len = 0;
    uint16_t encoded_public_key_len = 0;
    uint32_t next_len;

    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;
    param_set_id = PARAM_SET_IDS[_i];

    /* Get public/private key lengths */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                         NULL, &private_key_len, NULL);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));
    ck_assert_uint_gt(public_key_len, 0);
    ck_assert_uint_gt(private_key_len, 0);

    /* Allocate storage for keys */
    public_key = ntru_ck_malloc(&public_key_mem, public_key_len);
    private_key = ntru_ck_malloc(&private_key_mem, private_key_len);

    /* Generate key */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id,
                                         &public_key_len, public_key,
                                         &private_key_len, private_key);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* Check public key validity and get maximum ciphertext length */
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key, 0, NULL,
                                  &ciphertext_len, NULL);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* Check private key validity and get maximum plaintext length */
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key, 0, NULL,
                                  &max_msg_len, NULL);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* Allocate memory for plaintexts/ciphertexts */
    message = ntru_ck_malloc(&message_mem, (1 + max_msg_len));
    ciphertext = ntru_ck_malloc(&ciphertext_mem, ciphertext_len);
    plaintext = ntru_ck_malloc(&plaintext_mem, max_msg_len);

    /* Encrypt/decrypt at every valid message length */
    for(mlen=0; mlen<=max_msg_len; mlen++)
    {
      plaintext_len = max_msg_len;
      randombytes(message, mlen);
      randombytes(ciphertext, ciphertext_len);
      randombytes(plaintext, plaintext_len);

      rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                    mlen, message, &ciphertext_len, ciphertext);
      ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

      rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                    ciphertext_len, ciphertext,
                                    &plaintext_len, plaintext);
      ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

      ck_assert_uint_eq(plaintext_len, mlen);
      ck_assert_int_eq(memcmp(plaintext,message,mlen), 0);
    }

    randombytes(message, 1+max_msg_len);
    memset(ciphertext, 0, ciphertext_len);
    memset(plaintext, 0, plaintext_len);

    /* Begin checking error cases */

    /*
     * KeyGen Error Cases
     */
    /* Generate a key with unknown parameter set */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, -1,
                                         &public_key_len, public_key,
                                         &private_key_len, private_key);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_INVALID_PARAMETER_SET));

    /* Public key buffer length not provided */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id,
                                         NULL, public_key,
                                         NULL, private_key);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PARAMETER));

    /* Public key buffer is too short */
    public_key_len -= 1;
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id,
                                         &public_key_len, public_key,
                                         &private_key_len, private_key);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BUFFER_TOO_SMALL));
    public_key_len += 1;

    /* Private key buffer is too short */
    private_key_len -= 1;
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id,
                                         &public_key_len, public_key,
                                         &private_key_len, private_key);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BUFFER_TOO_SMALL));
    private_key_len += 1;


    /*
     * Encrypt Error Cases
     */
    /* Public key not provided */
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, NULL,
                                  max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PARAMETER));

    /* Public key length zero */
    rc = ntru_crypto_ntru_encrypt(drbg, 0, public_key,
                                  max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_LENGTH));

    /* Public key truncated */
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len-1, public_key,
                                  max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PUBLIC_KEY));

    /* Public key severely truncated */
    rc = ntru_crypto_ntru_encrypt(drbg, 4, public_key,
                                  max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PUBLIC_KEY));

    /* Public key has OID field of length != 3 */
    public_key[1] = 255;
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                  max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PUBLIC_KEY));
    public_key[1] = 3;

    /* Public key has private key tag */
    tag = public_key[0];
    public_key[0] = 0x02;
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                  max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PUBLIC_KEY));

    /* Public key has unrecognized tag */
    public_key[0] = 0xaa;
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                  max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PUBLIC_KEY));
    public_key[0] = tag;

    /* Plaintext not provided */
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                  max_msg_len, NULL,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PARAMETER));

    /* Plaintext that is too long */
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                  1+max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_LENGTH));

    /* Ciphertext buffer that is too short */
    ciphertext_len -= 1;
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                  max_msg_len, message,
                                  &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BUFFER_TOO_SMALL));
    ciphertext_len += 1;

    /* Perform a good encryption before testing decryption */
    randombytes(message, max_msg_len);
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                  max_msg_len, message, &ciphertext_len, ciphertext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /*
     * Decrypt Error Cases
     */
    /* Private key not provided */
    rc = ntru_crypto_ntru_decrypt(private_key_len, NULL,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PARAMETER));

    /* Private key length zero */
    rc = ntru_crypto_ntru_decrypt(0, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_LENGTH));

    /* Private key truncated */
    rc = ntru_crypto_ntru_decrypt(private_key_len-10, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PRIVATE_KEY));

    /* Private key has public key tag */
    tag = private_key[0];
    private_key[0] = 0x01;
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PRIVATE_KEY));
    private_key[0] = tag;

    /* Private key has bad OID */
    private_key[3] ^= 0xff;
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PRIVATE_KEY));
    private_key[3] ^= 0xff;

    /* Ciphertext not provided */
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len, NULL,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PARAMETER));

    /* Ciphertext truncated */
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len-10, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_LENGTH));

    /* Ciphertext manipulated */
    ciphertext[ciphertext_len>>1] ^= 0xff;
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_FAIL));
    ciphertext[ciphertext_len>>1] ^= 0xff;

    /* Plaintext buffer too short */
    plaintext_len -= 1;
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BUFFER_TOO_SMALL));
    plaintext_len += 1;

    /* Overwrite key pair and try decrypt with wrong key */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id,
                                         &public_key_len, public_key,
                                         &private_key_len, private_key);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_FAIL));

    /* Try decrypting junk */
    randombytes(ciphertext, ciphertext_len);
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                  ciphertext_len, ciphertext,
                                  &plaintext_len, plaintext);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_FAIL));


    /* Check x509 encoding/decoding */

    /* Get encoded public key size */
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len, NULL);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* Perform the encoding */
    encoded_public_key = ntru_ck_malloc(&encoded_public_key_mem,
            encoded_public_key_len);

    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len,
            encoded_public_key);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* Get the decoded public key size */
    next = encoded_public_key;
    next_len = encoded_public_key_len;
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key2_len, NULL, &next, &next_len);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));
    ck_assert_uint_eq(public_key_len, public_key2_len);
    ck_assert_uint_eq(next_len, encoded_public_key_len);
    ck_assert_ptr_eq(next, encoded_public_key);

    /* Perform the decoding */
    public_key2 = ntru_ck_malloc(&public_key2_mem, public_key2_len);

    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key2_len, public_key2, &next, &next_len);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));
    ck_assert_uint_eq(next_len, 0);
    ck_assert_ptr_eq(next, NULL);

    /* Check decoded key matches original */
    ck_assert_uint_eq(public_key_len, public_key2_len);
    ck_assert_int_eq(memcmp(public_key,public_key2,public_key_len), 0);

    /* Test error cases */
    next = encoded_public_key;
    next_len = encoded_public_key_len;
    /* Public key to be encoded is not provided */
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, NULL, &encoded_public_key_len, next);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PARAMETER));

    /* Public key to be encoded is length zero */
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            0, public_key, &encoded_public_key_len, next);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_LENGTH));

    /* Public key is corrupted */
    public_key[0] ^= 0xff;
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len, next);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PUBLIC_KEY));
    public_key[0] ^= 0xff;

    /* Encoded public key buffer too short */
    encoded_public_key_len -= 1;
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len,
            encoded_public_key);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BUFFER_TOO_SMALL));
    encoded_public_key_len += 1;

    /* Encoded data not provided */
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(NULL,
            &public_key2_len, public_key2, &next, &next_len);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_PARAMETER));

    /* Encoded data truncated */
    next_len = encoded_public_key_len-1;
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key2_len, public_key2, &next, &next_len);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_LENGTH));
    next_len = encoded_public_key_len;

    /* Encoded data of length less than prefix */
    next_len = 17;
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key2_len, public_key2, &next, &next_len);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_LENGTH));
    next_len = encoded_public_key_len;

    /* Buffer for decoded key too short */
    public_key2_len -= 1;
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key2_len, public_key2, &next, &next_len);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BUFFER_TOO_SMALL));
    public_key2_len += 1;


    /* Manipulate the DER id, should fail with OID_NOT_RECOGNIZED */
    tag = encoded_public_key[31];
    encoded_public_key[31] = 0xff;
    next = encoded_public_key;
    next_len = encoded_public_key_len;
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key2_len, public_key2, &next, &next_len);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OID_NOT_RECOGNIZED));
    encoded_public_key[31] = tag;

    /* Manipulate the template, should fail with BAD_ENCODING */
    memset(encoded_public_key, 18, 0xff);
    next = encoded_public_key;
    next_len = encoded_public_key_len;
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key2_len, public_key2, &next, &next_len);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_BAD_ENCODING));


    ntru_ck_mem_ok(&public_key2_mem);
    ntru_ck_mem_ok(&encoded_public_key_mem);
    ntru_ck_mem_ok(&message_mem);
    ntru_ck_mem_ok(&public_key_mem);
    ntru_ck_mem_ok(&private_key_mem);
    ntru_ck_mem_ok(&plaintext_mem);
    ntru_ck_mem_ok(&ciphertext_mem);

    ntru_ck_mem_free(&public_key2_mem);
    ntru_ck_mem_free(&encoded_public_key_mem);
    ntru_ck_mem_free(&message_mem);
    ntru_ck_mem_free(&public_key_mem);
    ntru_ck_mem_free(&private_key_mem);
    ntru_ck_mem_free(&plaintext_mem);
    ntru_ck_mem_free(&ciphertext_mem);
}
END_TEST


START_TEST(test_api_drbg_sha256_hmac)
{
    /* We run this as a loop test _i indexes the size */
    uint32_t sizes[] = {112, 128, 192, 256};
    uint32_t s_bits = sizes[_i];

    uint32_t i;
    uint32_t j;
    uint32_t rc;
    DRBG_HANDLE handles[DRBG_MAX_INSTANTIATIONS];
    DRBG_HANDLE extra;
    const uint8_t pers_str[] = "test_api_drbg";
    uint32_t pers_str_bytes = sizeof(pers_str);
    uint8_t pool[10];
    uint8_t pool2[sizeof(pool)];

    /* Internal SHA256 DRBG type */
    /* Bad parameters */
    rc = ntru_crypto_drbg_instantiate(-1, pers_str, pers_str_bytes,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy, handles+0);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_LENGTH));

    rc = ntru_crypto_drbg_instantiate(s_bits, NULL, pers_str_bytes,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy, handles+0);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    rc = ntru_crypto_drbg_instantiate(s_bits, pers_str,
            HMAC_DRBG_MAX_PERS_STR_BYTES+1,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy, handles+0);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_LENGTH));

    rc = ntru_crypto_drbg_instantiate(s_bits, pers_str, pers_str_bytes,
            NULL, handles+0);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    rc = ntru_crypto_drbg_instantiate(s_bits, pers_str, pers_str_bytes,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy, NULL);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    /* Bad entropy functions */
    /* Error in init */
    rc = ntru_crypto_drbg_instantiate(s_bits, pers_str, pers_str_bytes,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy_err_init, handles+0);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_ENTROPY_FAIL));

    /* Error in get_num */
    rc = ntru_crypto_drbg_instantiate(s_bits, pers_str, pers_str_bytes,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy_err_get_num, handles+0);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_ENTROPY_FAIL));

    /* get_num reports that source is perfectly predictable */
    rc = ntru_crypto_drbg_instantiate(s_bits, pers_str, pers_str_bytes,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy_err_num_eq_zero,
            handles+0);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_ENTROPY_FAIL));

    /* Error in get_byte */
    rc = ntru_crypto_drbg_instantiate(s_bits, pers_str, pers_str_bytes,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy_err_get_byte, handles+0);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_ENTROPY_FAIL));

    /* Instantiate as many HMAC DRBGs as we are allowed */
    for(i=0; i<DRBG_MAX_INSTANTIATIONS; i++)
    {
        rc = ntru_crypto_drbg_instantiate(s_bits, pers_str, pers_str_bytes,
                (ENTROPY_FN) drbg_sha256_hmac_get_entropy, handles+i);
        ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));
    }

    /* Check pairwise distinctness of handles */
    for(i=0; i<DRBG_MAX_INSTANTIATIONS-1; i++)
    {
        for(j=i+1; j<DRBG_MAX_INSTANTIATIONS; j++)
        {
            ck_assert_uint_ne(handles[i], handles[j]);
        }
    }

    /* Instantiate too many DRBGs */
    rc = ntru_crypto_drbg_instantiate(s_bits, pers_str, pers_str_bytes,
            (ENTROPY_FN) drbg_sha256_hmac_get_entropy, &extra);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_NOT_AVAILABLE));

    /* drbg_generate input checks */
    rc = ntru_crypto_drbg_generate(handles[0], s_bits, sizeof(pool), NULL);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    rc = ntru_crypto_drbg_generate(handles[0], s_bits, 0, pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_LENGTH));

    /* Use a DRBG */
    rc = ntru_crypto_drbg_generate(handles[0], s_bits, sizeof(pool), pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));

    /* Use a second DRBG */
    rc = ntru_crypto_drbg_generate(handles[1], s_bits, sizeof(pool2), pool2);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));

    /* Hopefully those outputs are different (w/ prob 2^-80) */
    ck_assert_int_ne(memcmp(pool, pool2, sizeof(pool)), 0);

    /* Reseed an HMAC DRBG (should not fail) */
    rc = ntru_crypto_drbg_reseed(handles[0]);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));

    /* Try to get zero bytes */
    rc = ntru_crypto_drbg_generate(handles[0], s_bits, 0, pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_LENGTH));

    /* Request too high of a security level */
    rc = ntru_crypto_drbg_generate(handles[0], 2*DRBG_MAX_SEC_STRENGTH_BITS,
                                   sizeof(pool), pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_LENGTH));

    /* Request too many bytes */
    rc = ntru_crypto_drbg_generate(handles[0], s_bits,
                                   1+HMAC_DRBG_MAX_BYTES_PER_REQUEST, pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_LENGTH));

    /* Uninstantiate DRBGs */
    for(i=0; i<DRBG_MAX_INSTANTIATIONS; i++)
    {
        rc = ntru_crypto_drbg_uninstantiate(handles[i]);
        ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));
    }

    /* Reseed a uninstantiated DRBG */
    rc = ntru_crypto_drbg_reseed(handles[0]);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    /* Double uninstantiate */
    rc = ntru_crypto_drbg_uninstantiate(handles[0]);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    /* Use an uninstantiated DRBG */
    rc = ntru_crypto_drbg_generate(handles[0], 0, 10, pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    /* Use a DRBG that never existed */
    handles[0] = 0xaabbccdd;
    rc = ntru_crypto_drbg_generate(handles[0], 0, 10, pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));
}
END_TEST

START_TEST(test_api_drbg_external)
{
    uint32_t i;
    uint32_t j;
    uint32_t rc;
    DRBG_HANDLE handles[DRBG_MAX_INSTANTIATIONS];
    DRBG_HANDLE extra;
    uint8_t pool[10];
    uint8_t pool2[sizeof(pool)];

    /* External DRBG type */
    /* Bad parameters */
    rc = ntru_crypto_drbg_external_instantiate(
            (RANDOM_BYTES_FN) &randombytes, NULL);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    rc = ntru_crypto_drbg_external_instantiate(NULL, handles);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    /* Instantiate as many external DRBGs as we are allowed */
    for(i=0; i<DRBG_MAX_INSTANTIATIONS; i++)
    {
        rc = ntru_crypto_drbg_external_instantiate(
                (RANDOM_BYTES_FN) &randombytes, handles+i);
        ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));
    }

    /* Check pairwise distinctness of handles */
    for(i=0; i<DRBG_MAX_INSTANTIATIONS-1; i++)
    {
        for(j=i+1; j<DRBG_MAX_INSTANTIATIONS; j++)
        {
            ck_assert_uint_ne(handles[i], handles[j]);
        }
    }

    /* Instantiate too many DRBGs */
    rc = ntru_crypto_drbg_external_instantiate(
            (RANDOM_BYTES_FN) &randombytes, &extra);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_NOT_AVAILABLE));

    /* Use a DRBG */
    rc = ntru_crypto_drbg_generate(handles[0], 0, sizeof(pool), pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));

    /* Use a second DRBG */
    rc = ntru_crypto_drbg_generate(handles[1], 0, sizeof(pool2), pool2);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));

    /* Hopefully those outputs are different (w/ prob 2^-80) */
    ck_assert_int_ne(memcmp(pool, pool2, sizeof(pool)), 0);

    /* Reseed an external DRBG (not implemented, should fail) */
    rc = ntru_crypto_drbg_reseed(handles[0]);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    /* Try to get zero bytes */
    rc = ntru_crypto_drbg_generate(handles[0], 0, 0, pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_LENGTH));

    /* Instantiate too many DRBGs */
    rc = ntru_crypto_drbg_external_instantiate(
            (RANDOM_BYTES_FN) &randombytes, &extra);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_NOT_AVAILABLE));

    /* Uninstantiate DRBGs */
    for(i=0; i<DRBG_MAX_INSTANTIATIONS; i++)
    {
        rc = ntru_crypto_drbg_uninstantiate(handles[i]);
        ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));
    }

    /* Use an uninstantiated DRBG */
    rc = ntru_crypto_drbg_generate(handles[0], 0, 10, pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));

    /* Use a DRBG that never existed */
    handles[0] = 0xaabbccdd;
    rc = ntru_crypto_drbg_generate(handles[0], 0, 10, pool);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_BAD_PARAMETER));
}
END_TEST

START_TEST(test_get_param_set_name)
{
    const char *name;
    name = ntru_encrypt_get_param_set_name(NTRU_EES401EP2);
    ck_assert_str_eq(name, "ees401ep2");
    name = ntru_encrypt_get_param_set_name(-1);
    ck_assert_ptr_eq((void *)name, NULL);
}
END_TEST

Suite *
ntruencrypt_public_test_suite(void)
{
    Suite *s;
    TCase *tc_api_crypto;
    TCase *tc_api_drbg;
    TCase *tc_api_misc;

    s = suite_create("NTRUEncrypt.Public");

    /* Test publicly accessible DRBG routines */
    tc_api_drbg = tcase_create("drbg");
    tcase_add_test(tc_api_drbg, test_api_drbg_external);
    tcase_add_loop_test(tc_api_drbg, test_api_drbg_sha256_hmac, 0, 4);

    /* Test publicly accessible crypto routines for each parameter set */
    tc_api_crypto = tcase_create("crypto");
    tcase_add_unchecked_fixture(tc_api_crypto, test_drbg_setup, test_drbg_teardown);
    tcase_add_loop_test(tc_api_crypto, test_api_crypto, 0, NUM_PARAM_SETS);

    tc_api_misc = tcase_create("misc");
    tcase_add_test(tc_api_misc, test_get_param_set_name);

    suite_add_tcase(s, tc_api_misc);
    suite_add_tcase(s, tc_api_drbg);
    suite_add_tcase(s, tc_api_crypto);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = ntruencrypt_public_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
