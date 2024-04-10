#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"
#include "test_common.h"

uint32_t randombytes(uint8_t *x, uint32_t xlen)
{
  static int fd = -1;
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom",O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
  DRBG_RET(DRBG_OK);
}


uint8_t
drbg_sha256_hmac_get_entropy(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{
    /* 48 bytes of entropy are needed to instantiate a DRBG with a
     * security strength of 256 bits.
     */
    static uint8_t seed[48];
    static size_t index;

    if (cmd == INIT)
    {
        /* Any initialization for a real entropy source goes here. */
        index = 0;
        randombytes(seed, sizeof(seed));
        return 1;
    }

    if (out == NULL)
        return 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY)
    {
        /* Here we return the number of bytes needed from the entropy
         * source to obtain 8 bits of entropy.  Maximum is 8.
         */
        *out = 1;       /* treat this as a perfectly random source */
        return 1;
    }

    if (cmd == GET_BYTE_OF_ENTROPY)
    {
        if (index >= sizeof(seed))
        {
            index = 0;
            randombytes(seed, sizeof(seed));
        }

        *out = seed[index++];           /* deliver an entropy byte */
        return 1;
    }
    return 0;
}

uint8_t
drbg_sha256_hmac_get_entropy_err_init(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{
    if (cmd == INIT)
    {
        return 0;
    }

    return drbg_sha256_hmac_get_entropy(cmd, out);
}

uint8_t
drbg_sha256_hmac_get_entropy_err_get_num(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{
    if (cmd == GET_BYTE_OF_ENTROPY)
    {
        return 0;
    }

    return drbg_sha256_hmac_get_entropy(cmd, out);
}

uint8_t
drbg_sha256_hmac_get_entropy_err_num_eq_zero(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{
    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY)
    {
        *out = 0;
        return 1;
    }

    return drbg_sha256_hmac_get_entropy(cmd, out);
}

uint8_t
drbg_sha256_hmac_get_entropy_err_get_byte(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{
    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY)
    {
        return 0;
    }

    return drbg_sha256_hmac_get_entropy(cmd, out);
}
