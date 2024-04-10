#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"
#include "test_common.h"

#define LOOPS 10000

int
main(int argc, char **argv)
{
    uint16_t i;
    uint32_t j;
    uint8_t *public_key;
    uint8_t *private_key;
    uint8_t *message;
    uint8_t *ciphertext;
    uint8_t *plaintext;

    uint16_t max_msg_len;
    uint16_t public_key_len;          /* no. of octets in public key */
    uint16_t private_key_len;         /* no. of octets in private key */
    uint16_t ciphertext_len;          /* no. of octets in ciphertext */
    uint16_t plaintext_len;           /* no. of octets in plaintext */
    DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
    uint32_t rc;                      /* return code */
    uint32_t loops = LOOPS;           /* number of loops when benchmarking */

    clock_t clk;

    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;

    uint32_t error[NUM_PARAM_SETS] = {0};

    for(i=0; i<NUM_PARAM_SETS; i++)
    {
      param_set_id = PARAM_SET_IDS[i];
      fprintf(stderr, "Testing parameter set %s... ", ntru_encrypt_get_param_set_name(param_set_id));
      fflush (stderr);

      rc = ntru_crypto_drbg_external_instantiate(
                                        (RANDOM_BYTES_FN) &randombytes, &drbg);

      if (rc != DRBG_OK)
      {
        fprintf(stderr,"\tError: An error occurred instantiating the DRBG\n");
        error[i] = 1;
        continue;
      }

      rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                           NULL, &private_key_len, NULL);
      if (rc != NTRU_OK)
      {
        ntru_crypto_drbg_uninstantiate(drbg);
        fprintf(stderr,"\tError: An error occurred getting the key lengths\n");
        error[i] = 1;
        continue;
      }

      public_key = (uint8_t *)malloc(public_key_len * sizeof(uint8_t));
      private_key = (uint8_t *)malloc(private_key_len * sizeof(uint8_t));

      clk = clock();
      for (j = 0; j < loops/10 || j < 1; j++)
      {
        rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                           public_key,
                                           &private_key_len,
                                           private_key);
        if (rc != NTRU_OK) break;
      }
      clk = clock() - clk;
      if (rc != NTRU_OK)
      {
        ntru_crypto_drbg_uninstantiate(drbg);
        free(public_key);
        free(private_key);
        fprintf(stderr,"\tError: An error occurred during key generation\n");
        error[i] = 1;
        continue;
      }

      if (loops) {
        fprintf(stderr, "kg %dus, ", (int)((1.0*clk)/(loops/10)));
        fflush (stderr);
      }

      rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key, 0, NULL,
                                    &ciphertext_len, NULL);
      if (rc != NTRU_OK)
      {
        fprintf(stderr,"\tError: Bad public key");
        error[i] = 1;
        continue;
      }

      rc = ntru_crypto_ntru_decrypt(private_key_len, private_key, 0, NULL,
                                    &max_msg_len, NULL);
      if (rc != NTRU_OK)
      {
        fprintf(stderr,"\tError: Bad private key");
        error[i] = 1;
        continue;
      }


      message = (uint8_t *) malloc(max_msg_len * sizeof(uint8_t));

      ciphertext = (uint8_t *) malloc(ciphertext_len * sizeof(uint8_t));

      plaintext = (uint8_t *) malloc(max_msg_len * sizeof(uint8_t));

      plaintext_len = max_msg_len;
      randombytes(message, max_msg_len);
      randombytes(ciphertext, ciphertext_len);
      randombytes(plaintext, plaintext_len);

      clk = clock();
      for (j = 0; j < loops || j < 1; j++)
      {
        rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
              max_msg_len, message, &ciphertext_len, ciphertext);
        if(rc != NTRU_OK) break;
      }
      clk = clock() - clk;
      if (rc != NTRU_OK){
        fprintf(stderr, "\tError: Encryption error %x\n", rc);
        error[i] = 1;
        break;
      }

      if (loops) {
        fprintf(stderr, "e %dus, ", (int)((1.0*clk)/loops));
        fflush (stderr);
      }

      clk = clock();
      for (j = 0; j < loops || j < 1; j++)
      {
        rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
              ciphertext_len, ciphertext,
              &plaintext_len, plaintext);
        if(rc != NTRU_OK) break;
      }
      clk = clock() - clk;
      if (rc != NTRU_OK)
      {
        fprintf(stderr, "\tError: Decryption error %x\n", rc);
        error[i] = 1;
        break;
      }

      if (loops) {
        fprintf(stderr, "d %dus", (int)((1.0*clk)/loops));
      }

      if(plaintext_len != max_msg_len || memcmp(plaintext,message,max_msg_len))
      {
        fprintf(stderr,
          "\tError: Decryption result does not match original plaintext\n");
        error[i] = 1;
        break;
      }

      ntru_crypto_drbg_uninstantiate(drbg);
      free(message);
      free(public_key);
      free(private_key);
      free(plaintext);
      free(ciphertext);

      fprintf(stderr, "\t pk %d, sk %d, ct %d bytes",
              public_key_len, private_key_len-public_key_len, ciphertext_len);
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
