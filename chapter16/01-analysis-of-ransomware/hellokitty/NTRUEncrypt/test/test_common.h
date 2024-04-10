#ifndef NTRU_TEST_COMMON_H
#define NTRU_TEST_COMMON_H

/* Common components for all test programs */

uint32_t randombytes(uint8_t *x,uint32_t xlen);

/* HMAC SHA256 entropy functions */
uint8_t
drbg_sha256_hmac_get_entropy(ENTROPY_CMD cmd, uint8_t *out);

uint8_t
drbg_sha256_hmac_get_entropy_err_init(ENTROPY_CMD cmd, uint8_t *out);

uint8_t
drbg_sha256_hmac_get_entropy_err_get_num(ENTROPY_CMD cmd, uint8_t *out);

uint8_t
drbg_sha256_hmac_get_entropy_err_num_eq_zero(ENTROPY_CMD cmd, uint8_t *out);

uint8_t
drbg_sha256_hmac_get_entropy_err_get_byte(ENTROPY_CMD cmd, uint8_t *out);

/* List of parameter sets */

static const NTRU_ENCRYPT_PARAM_SET_ID PARAM_SET_IDS[] = {
  NTRU_EES401EP1, NTRU_EES449EP1, NTRU_EES677EP1, NTRU_EES1087EP2,
  NTRU_EES541EP1, NTRU_EES613EP1, NTRU_EES887EP1, NTRU_EES1171EP1,
  NTRU_EES659EP1, NTRU_EES761EP1, NTRU_EES1087EP1, NTRU_EES1499EP1,
  NTRU_EES401EP2, NTRU_EES439EP1, NTRU_EES593EP1, NTRU_EES743EP1,
  NTRU_EES443EP1, NTRU_EES587EP1
};
#define NUM_PARAM_SETS (sizeof(PARAM_SET_IDS)/sizeof(PARAM_SET_IDS[0]))

#endif
