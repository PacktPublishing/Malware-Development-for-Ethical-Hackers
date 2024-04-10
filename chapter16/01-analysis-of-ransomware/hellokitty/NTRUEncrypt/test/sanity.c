#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"
#include "test_common.h"

/* For each parameter set:
 *    - Generate a key
 *    - Encrypt a message at every length between
 *      0 and maxMsgLenBytes.
 *    - Check that decryption succeeds.
 *    - Check that decryption fails for bad ciphertexts
 */

int
main(int argc, char **argv)
{
    uint16_t i;
    uint8_t *public_key;
    uint8_t *private_key;
    uint8_t *message;
    uint8_t *ciphertext;
    uint8_t *plaintext;

    uint16_t max_msg_len;
    uint16_t mlen;
    uint16_t public_key_len;          /* no. of octets in public key */
    uint16_t private_key_len;         /* no. of octets in private key */
    uint16_t ciphertext_len;          /* no. of octets in ciphertext */
    uint16_t plaintext_len;           /* no. of octets in plaintext */
    DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
    uint32_t rc;                      /* return code */

    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;

    uint32_t error[NUM_PARAM_SETS] = {0};

    for(i=0; i<NUM_PARAM_SETS; i++)
    {
      param_set_id = PARAM_SET_IDS[i];
      fprintf(stderr, "Testing parameter set %s... ",
          ntru_encrypt_get_param_set_name(param_set_id));
      fflush (stderr);

      rc = ntru_crypto_drbg_external_instantiate(
                                        (RANDOM_BYTES_FN) &randombytes, &drbg);

      if (rc != DRBG_OK)
      {
        fprintf(stderr,"\tError: An error occurred instantiating the DRBG\n");
        error[i] = 1;
        continue;
      }

      /* Get public/private key lengths */
      rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                           NULL, &private_key_len, NULL);
      if (rc != NTRU_OK)
      {
        ntru_crypto_drbg_uninstantiate(drbg);
        fprintf(stderr,"\tError: An error occurred getting the key lengths\n");
        error[i] = 1;
        continue;
      }

      /* Generate a key */
      public_key = (uint8_t *)malloc(public_key_len * sizeof(uint8_t));
      private_key = (uint8_t *)malloc(private_key_len * sizeof(uint8_t));
      rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                         public_key,
                                         &private_key_len,
                                         private_key);
      if (rc != NTRU_OK)
      {
        ntru_crypto_drbg_uninstantiate(drbg);
        free(public_key);
        free(private_key);
        fprintf(stderr,"\tError: An error occurred during key generation\n");
        error[i] = 1;
        continue;
      }

      /* Check public key validity and get maximum ciphertext length */
      rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key, 0, NULL,
                                    &ciphertext_len, NULL);
      if (rc != NTRU_OK)
      {
        fprintf(stderr,"\tError: Bad public key");
        error[i] = 1;
        continue;
      }

      /* Check private key validity and get maximum plaintext length */
      rc = ntru_crypto_ntru_decrypt(private_key_len, private_key, 0, NULL,
                                    &max_msg_len, NULL);
      if (rc != NTRU_OK)
      {
        fprintf(stderr,"\tError: Bad private key");
        error[i] = 1;
        continue;
      }

      /* Allocate memory for plaintexts/ciphertexts */
      message = (uint8_t *) malloc(max_msg_len * sizeof(uint8_t));
      ciphertext = (uint8_t *) malloc(ciphertext_len * sizeof(uint8_t));
      plaintext = (uint8_t *) malloc(max_msg_len * sizeof(uint8_t));

      /* Encrypt/decrypt at every valid message length */
      for(mlen=0; mlen<=max_msg_len; mlen++)
      {
        plaintext_len = max_msg_len;
        randombytes(message, mlen);
        randombytes(ciphertext, ciphertext_len);
        randombytes(plaintext, plaintext_len);

        rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
              mlen, message, &ciphertext_len, ciphertext);
        if (rc != NTRU_OK){
          fprintf(stderr, "\tError: Encryption error %x\n", rc);
          error[i] = 1;
          break;
        }

        rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
              ciphertext_len, ciphertext,
              &plaintext_len, plaintext);
        if (rc != NTRU_OK)
        {
          fprintf(stderr, "\tError: Decryption error %x\n", rc);
          error[i] = 1;
          break;
        }

        if(plaintext_len != mlen || memcmp(plaintext,message,mlen))
        {
          fprintf(stderr,
            "\tError: Decryption result does not match original plaintext\n");
          error[i] = 1;
          break;
        }
      }

      /* Try decrypting junk */
      randombytes(ciphertext, ciphertext_len);
      rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
            ciphertext_len, ciphertext,
            &plaintext_len, plaintext);
      if (rc != NTRU_RESULT(NTRU_FAIL))
      {
        fprintf(stderr, "\tError: Accepted junk ciphertext\n");
        error[i] = 1;
        break;
      }

      ntru_crypto_drbg_uninstantiate(drbg);
      free(message);
      free(public_key);
      free(private_key);
      free(plaintext);
      free(ciphertext);
      fprintf(stderr, "\n");
    }

    for(i=0; i<NUM_PARAM_SETS; i++) {
      if(error[i]) {
        fprintf(stderr, "Result: Fail\n");
        return 1;
      }
    }

    fprintf(stderr, "Result: Pass\n");
    return 0;
}
