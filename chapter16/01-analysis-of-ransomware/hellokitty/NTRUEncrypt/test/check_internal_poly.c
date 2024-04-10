#include <check.h>

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_encrypt_param_sets.h"
#include "ntru_crypto_ntru_mgf1.h"
#include "ntru_crypto_ntru_poly.h"

#include "test_common.h"
#include "check_common.h"

START_TEST(test_gen_poly)
{

    uint32_t  rc;
    uint32_t  i;
    uint32_t  j;

    uint8_t   md_len;
    uint16_t  seed_len;
    uint16_t  mgf_buf_len;
    uint16_t  num_indices = 0;

    NTRU_ENCRYPT_PARAM_SET *params = NULL;
    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;
    NTRU_CRYPTO_HASH_ALGID  hash_algid;

    uint8_t  *seed_buf_p;
    uint8_t  *mgf_buf_p;
    uint16_t  *F_buf_1_p;
    uint16_t  *F_buf_2_p;

    NTRU_CK_MEM seed_buf;
    NTRU_CK_MEM mgf_buf;
    NTRU_CK_MEM F_buf_1;
    NTRU_CK_MEM F_buf_2;

    /* Get the parameter set */
    param_set_id = PARAM_SET_IDS[_i];
    params = ntru_encrypt_get_params_with_id(param_set_id);
    ck_assert_ptr_ne(params, NULL);

    if (params->hash_algid == NTRU_CRYPTO_HASH_ALGID_SHA1)
    {
        hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA1;
        md_len = SHA_1_MD_LEN;
    }
    else if (params->hash_algid == NTRU_CRYPTO_HASH_ALGID_SHA256)
    {
        hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA256;
        md_len = SHA_256_MD_LEN;
    }
    else
    {
        ck_assert(0);
    }

    seed_len = 2 * params->sec_strength_len;
    mgf_buf_len = 4 + params->N + md_len * (1+params->min_IGF_hash_calls);

    if(params->is_product_form)
    {
        /* Need 2 * (dF1 + dF2 + dF3) indices) */
        num_indices = (params->dF_r & 0x000000ff);
        num_indices += (params->dF_r & 0x0000ff00) >> 8;
        num_indices += (params->dF_r & 0x00ff0000) >> 16;
        num_indices *= 2;
    }
    else
    {
        num_indices = 2 * params->dF_r;
    }

    seed_buf_p = ntru_ck_malloc(&seed_buf, seed_len*sizeof(*seed_buf_p));
    mgf_buf_p = ntru_ck_malloc(&mgf_buf, mgf_buf_len*sizeof(*mgf_buf_p));
    F_buf_1_p = (uint16_t *) ntru_ck_malloc(&F_buf_1,
            num_indices*sizeof(F_buf_1_p));
    F_buf_2_p = (uint16_t *) ntru_ck_malloc(&F_buf_2,
            num_indices*sizeof(F_buf_2_p));

    /* Generate a random seed */
    rc = ntru_crypto_drbg_generate(drbg, params->sec_strength_len << 3,
                                   seed_len, seed_buf_p);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));

    /* Generate an "F" type polynomial for this parameter set */
    rc = ntru_gen_poly(hash_algid, md_len,
                       params->min_IGF_hash_calls,
                       seed_len, seed_buf_p, mgf_buf_p,
                       params->N, params->c_bits,
                       params->no_bias_limit,
                       params->is_product_form,
                       params->dF_r << 1, F_buf_1_p);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* Check that indices are pairwise distinct (per poly for prod-form) */
    if(params->is_product_form)
    {
        uint16_t *Fp;
        uint32_t c;

        Fp = F_buf_1_p;
        c = params->dF_r << 1;
        while(c > 0) /* High byte of c is 0x00 */
        {
            for(i=0; i<(c&0xff)-1; i++)
            {
                for(j=i+1; j<(c&0xff); j++)
                {
                    ck_assert_uint_ne(Fp[i], Fp[j]);
                }
            }
            Fp += c & 0xff;
            c >>= 8;
        }
    }
    else
    {
        for(i=0; i<2*params->dF_r - 1; i++)
        {
            for(j=i+1; j<2*params->dF_r; j++)
            {
                ck_assert_uint_ne(F_buf_1_p[i], F_buf_1_p[j]);
            }
        }
    }

    /* Check that we get the same polynomial if we reuse the seed */
    rc = ntru_gen_poly(hash_algid, md_len,
                       params->min_IGF_hash_calls,
                       seed_len, seed_buf_p, mgf_buf_p,
                       params->N, params->c_bits,
                       params->no_bias_limit,
                       params->is_product_form,
                       params->dF_r << 1, F_buf_2_p);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));
    ck_assert_int_eq(
            memcmp(F_buf_1_p, F_buf_2_p, num_indices*sizeof(uint16_t)), 0);

    /* Check some failure cases */
    /* Trigger an mgf failure with an unknown hash_algid */
    rc = ntru_gen_poly(-1, md_len,
                       params->min_IGF_hash_calls,
                       seed_len, seed_buf_p, mgf_buf_p,
                       params->N, params->c_bits,
                       params->no_bias_limit,
                       params->is_product_form,
                       params->dF_r << 1, F_buf_2_p);
    ck_assert_uint_ne(rc, NTRU_RESULT(NTRU_OK));


    ntru_ck_mem_ok(&F_buf_2);
    ntru_ck_mem_ok(&F_buf_1);
    ntru_ck_mem_ok(&mgf_buf);
    ntru_ck_mem_ok(&seed_buf);

    ntru_ck_mem_free(&F_buf_2);
    ntru_ck_mem_free(&F_buf_1);
    ntru_ck_mem_free(&mgf_buf);
    ntru_ck_mem_free(&seed_buf);
}
END_TEST


START_TEST(test_min_weight)
{
    uint8_t tpoly1[13] = {2, 2, 2, 2, 0, 0, 0, 0, 0, 1, 1, 1, 1};
    ck_assert_int_eq(ntru_poly_check_min_weight(13, tpoly1, 4), TRUE);
    ck_assert_int_eq(ntru_poly_check_min_weight(13, tpoly1, 5), FALSE);
}
END_TEST

/* test_inv_mod_2
 *
 * Compares the result of ntru_ring_inv to a fixed value precomputed
 * with Pari/GP. Also checks that non-trivial non-invertible elements (factors
 * of x^N - 1 mod 2) are recognized as such.
 */
START_TEST(test_inv_mod_2)
{
    uint16_t tmp[34];
    uint16_t out[17];

    uint16_t a[17] = {1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1};
    uint16_t test_a[17] = {1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1};

    uint16_t b[17] = {1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};

    /* a is invertible with inverse equal to test_a */
    ck_assert_int_eq(ntru_ring_inv(a, 17, tmp, out), TRUE);
    ck_assert_int_eq(memcmp(out, test_a, sizeof(a)), 0);

    /* Test error cases */
    /* Changing the parity of a makes it trivially non-invertible */
    a[0] = 0;
    ck_assert_int_eq(ntru_ring_inv(a, 17, tmp, out), FALSE);

    /* b is a nontrivial factor of x^17 - 1 mod 2 */
    ck_assert_int_eq(ntru_ring_inv(b, 17, tmp, out), FALSE);

    /* Input not provided */
    ck_assert_int_eq(ntru_ring_inv(NULL, 17, tmp, out), FALSE);
    ck_assert_int_eq(ntru_ring_inv(a, 17, NULL, out), FALSE);
    ck_assert_int_eq(ntru_ring_inv(a, 17, tmp, NULL), FALSE);
}
END_TEST
/* test_lift_inv_mod_pow2
 */
START_TEST(test_lift_inv_mod_pow2)
{
    uint32_t i;
    uint16_t f_inv2[17] = {1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1};

    uint16_t f1l = 2;
    uint16_t f2l = 2;
    uint16_t f3l = 3;
    uint16_t fprod[14] = {7, 10, 9, 13, 1, 13, 6, 8, 4, 10, 11, 6, 9, 15};
    uint16_t f[17] = {4, 65533, 3, 3, 6, 65533, 0, 0, 3, 65530, 0, 6, 0,
        65533, 65533, 65533, 65533};

    uint16_t inv_test[17] = {7319, 52697, 32987, 43221, 48819, 42807, 18160,
        1250, 48426, 16935, 30796, 41596, 5768, 33264, 16639, 54271, 29334};

    uint16_t N = 17;
    uint16_t q = 0;

    NTRU_CK_MEM scratch;
    uint16_t * scratch_p;

    NTRU_CK_MEM pol1;
    NTRU_CK_MEM pol2;
    uint16_t * pol1_p;
    uint16_t * pol2_p;

    uint16_t scratch_polys;
    uint16_t pad_deg;
    ntru_ring_mult_coefficients_memreq(N, &scratch_polys, &pad_deg);
    ck_assert_uint_ge(scratch_polys, 1);
    ck_assert_uint_ge(pad_deg, N);

    /* Allocate memory */
    scratch_p = (uint16_t*)ntru_ck_malloc(&scratch,
            (1+scratch_polys) * pad_deg * sizeof(uint16_t));
    pol1_p = (uint16_t*)ntru_ck_malloc(&pol1, pad_deg * sizeof(uint16_t));
    pol2_p = (uint16_t*)ntru_ck_malloc(&pol2, pad_deg * sizeof(uint16_t));

    /* We should be able to work with dirty scratch space */
    randombytes(scratch.ptr, scratch.len);

    /* Copy and pad the inputs */
    memset(pol1.ptr, 0, pol1.len);
    memset(pol2.ptr, 0, pol2.len);
    memcpy(pol1_p, f_inv2, N*sizeof(uint16_t));
    memcpy(pol2_p, f, N*sizeof(uint16_t));

    /* Lift the inverse with f in coefficient form and check */
    ntru_ring_lift_inv_pow2_standard(pol1_p, pol2_p, N, q, scratch_p);
    for(i=0; i<N; i++)
    {
        ck_assert_uint_eq(pol1_p[i], inv_test[i]);
    }
    for(; i<pad_deg; i++)
    {
        ck_assert_uint_eq(pol1_p[i], 0);
    }


    randombytes(scratch.ptr, scratch.len);
    memset(pol1.ptr, 0, pol1.len);
    memcpy(pol1_p, f_inv2, N*sizeof(uint16_t));

    /* Lift the inverse with f in product form and check */
    ntru_ring_lift_inv_pow2_product(pol1_p, f1l, f2l, f3l, fprod, N, q, scratch_p);
    for(i=0; i<N; i++)
    {
        ck_assert_uint_eq(pol1_p[i], inv_test[i]);
    }
    for(; i<pad_deg; i++)
    {
        ck_assert_uint_eq(pol1_p[i], 0);
    }

    ntru_ck_mem_ok(&scratch);
    ntru_ck_mem_ok(&pol1);
    ntru_ck_mem_ok(&pol2);

    ntru_ck_mem_free(&scratch);
    ntru_ck_mem_free(&pol1);
    ntru_ck_mem_free(&pol2);
}
END_TEST


/* test_mult_indices
 *
 * Performs both ntru_ring_mult_indices and ntru_ring_mult_product_indices
 * and compares the result with a fixed example generated with Pari/GP.
 */
START_TEST(test_mult_indices)
{
    uint32_t i;
    uint16_t a[17] = {36486, 20395, 8746, 16637, 26195, 1654, 24222, 13306,
                    9573, 26946, 29106, 2401, 32146, 2871, 41930, 7902, 3398};
    uint16_t b1l = 2;
    uint16_t b2l = 2;
    uint16_t b3l = 3;
    uint16_t bi[14] = {7, 10, 9, 13, 1, 13, 6, 8, 4, 10, 11, 6, 9, 15};
    uint16_t test_single[17] = {6644, 48910, 5764, 16270, 2612, 10231, 769,
        2577, 58289, 38323, 56334, 29942, 55901, 43714, 17452, 43795, 21225};
    uint16_t test_prod[17] = {40787, 24792, 27808, 13989, 56309, 37625, 37436,
        32307, 15311, 59789, 32769, 65008, 3711, 54663, 25343, 55984, 6193};

    uint16_t N = 17;
    uint16_t q = 0;

    NTRU_CK_MEM pol1;
    NTRU_CK_MEM t;
    NTRU_CK_MEM out;

    uint16_t *pol1_p;
    uint16_t *t_p;
    uint16_t *out_p;

    uint16_t scratch_polys;
    uint16_t pad_deg;
    ntru_ring_mult_indices_memreq(N, &scratch_polys, &pad_deg);
    ck_assert_uint_ge(scratch_polys, 1);
    ck_assert_uint_ge(pad_deg, N);

    pol1_p = (uint16_t*)ntru_ck_malloc(&pol1, pad_deg*sizeof(*pol1_p));
    t_p = (uint16_t*)ntru_ck_malloc(&t, (scratch_polys+1)*pad_deg*sizeof(*t_p));
    out_p = (uint16_t*)ntru_ck_malloc(&out, pad_deg*sizeof(*out_p));

    /* Copy and pad the input */
    memset(pol1.ptr, 0, pol1.len);
    memcpy(pol1_p, a, N*sizeof(uint16_t));

    /* We should be able to work with dirty scratch and output memory */
    randombytes(t.ptr, t.len);
    randombytes(out.ptr, out.len);

    /* Test a single mult_indices first */
    ntru_ring_mult_indices(pol1_p, b1l, b1l, bi, N, q, t_p, out_p);
    /* Check result */
    for(i=0; i<N; i++)
    {
        ck_assert_uint_eq(out_p[i], test_single[i]);
    } /* Check padding is zero */
    for(; i<pad_deg; i++)
    {
        ck_assert_uint_eq(out_p[i], 0);
    }

    /* Check over/under runs */
    ntru_ck_mem_ok(&pol1);
    ntru_ck_mem_ok(&t);
    ntru_ck_mem_ok(&out);

    /* Now try a full product form multiplication */
    randombytes(t.ptr, t.len);
    randombytes(out.ptr, out.len);

    /* Multiply */
    ntru_ring_mult_product_indices(pol1_p, b1l, b2l, b3l, bi, N, q, t_p, out_p);

    /* Check result */
    for(i=0; i<N; i++)
    {
        ck_assert_uint_eq(out_p[i], test_prod[i]);
    } /* Check padding is zero */
    for(; i<pad_deg; i++)
    {
        ck_assert_uint_eq(out_p[i], 0);
    }

    /* Check over/under runs */
    ntru_ck_mem_ok(&pol1);
    ntru_ck_mem_ok(&t);
    ntru_ck_mem_ok(&out);

    ntru_ck_mem_free(&pol1);
    ntru_ck_mem_free(&t);
    ntru_ck_mem_free(&out);
}
END_TEST


START_TEST(test_mult_coefficients)
{
    uint32_t i;
    uint16_t a[17] = {36486, 20395, 8746, 16637, 26195, 1654, 24222, 13306,
                9573, 26946, 29106, 2401, 32146, 2871, 41930, 7902, 3398};
    uint16_t b[17] = {5266, 35261, 54826, 45380, 46459, 46509, 56767, 46916,
                33670, 11921, 46519, 47628, 20388, 4167, 39405, 2712, 52748};
    uint16_t test[17] = {30101, 45125, 62370, 2275, 34473, 7074, 62574, 57665,
                5199, 4482, 49487, 17159, 33125, 11061, 19328, 22268, 46230};

    uint16_t N = 17;
    uint16_t q = 0;

    /* Determine proper padding for our mult implementation */
    uint16_t num_polys;
    uint16_t num_coeffs;
    ntru_ring_mult_coefficients_memreq(N, &num_polys, &num_coeffs);

    /* Allocate memory */
    NTRU_CK_MEM pol1;
    NTRU_CK_MEM pol2;
    NTRU_CK_MEM tmp;
    NTRU_CK_MEM out;

    uint16_t *a_p;
    uint16_t *b_p;
    uint16_t *tmp_p;
    uint16_t *out_p;

    a_p = (uint16_t*)ntru_ck_malloc(&pol1, num_coeffs*sizeof(uint16_t));
    b_p = (uint16_t*)ntru_ck_malloc(&pol2, num_coeffs*sizeof(uint16_t));
    tmp_p = (uint16_t*)ntru_ck_malloc(&tmp,
            num_polys*num_coeffs*sizeof(uint16_t));
    out_p = (uint16_t*)ntru_ck_malloc(&out, num_coeffs*sizeof(uint16_t));

    /* Copy and pad the inputs */
    memcpy(a_p, a, N*sizeof(uint16_t));
    memcpy(b_p, b, N*sizeof(uint16_t));
    memset(a_p+N, 0, (num_coeffs-N)*sizeof(uint16_t));
    memset(b_p+N, 0, (num_coeffs-N)*sizeof(uint16_t));

    /* Should work with dirty scratch and output memory */
    randombytes(tmp.ptr+N, (num_coeffs-N)*sizeof(uint16_t));
    randombytes(out.ptr, out.len);

    /* Multiply */
    ntru_ring_mult_coefficients(a_p, b_p, N, q, tmp_p, out_p);

    /* Check result */
    for(i=0; i<N; i++)
    {
        ck_assert_uint_eq(out_p[i], test[i]);
    } /* Padding should be zero */
    for(; i<num_coeffs; i++)
    {
        ck_assert_uint_eq(out_p[i], 0);
    }

    /* Check over/under runs */
    ntru_ck_mem_ok(&pol1);
    ntru_ck_mem_ok(&pol2);
    ntru_ck_mem_ok(&tmp);
    ntru_ck_mem_ok(&out);

    ntru_ck_mem_free(&pol1);
    ntru_ck_mem_free(&pol2);
    ntru_ck_mem_free(&tmp);
    ntru_ck_mem_free(&out);
}
END_TEST


Suite *
ntruencrypt_internal_poly_suite(void)
{
    Suite *s;
    TCase *tc_poly;

    s = suite_create("NTRUEncrypt.Internal.Poly");

    tc_poly = tcase_create("Poly");
    tcase_add_unchecked_fixture(tc_poly, test_drbg_setup, test_drbg_teardown);
    tcase_add_loop_test(tc_poly, test_gen_poly, 0, NUM_PARAM_SETS);
    tcase_add_test(tc_poly, test_min_weight);
    tcase_add_test(tc_poly, test_inv_mod_2);
    tcase_add_test(tc_poly, test_lift_inv_mod_pow2);
    tcase_add_test(tc_poly, test_mult_indices);
    tcase_add_test(tc_poly, test_mult_coefficients);

    suite_add_tcase(s, tc_poly);

    return s;
}
