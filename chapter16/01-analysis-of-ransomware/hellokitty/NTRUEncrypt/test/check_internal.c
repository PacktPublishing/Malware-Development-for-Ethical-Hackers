#include <check.h>

#include "ntru_crypto.h"
#include "check_common.h"

int
main(void)
{
    int number_failed;
    SRunner *sr;

    sr = srunner_create(ntruencrypt_internal_poly_suite());
    srunner_add_suite(sr, ntruencrypt_internal_key_suite());
    srunner_add_suite(sr, ntruencrypt_internal_sha_suite());
    srunner_add_suite(sr, ntruencrypt_internal_mgf_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
