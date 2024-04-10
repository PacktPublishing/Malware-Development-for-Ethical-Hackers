AUTOMAKE_OPTIONS = foreign 1.9 subdir-objects
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I$(top_srcdir)/include
AM_CFLAGS += -Wall -Wshadow
if COVERAGE_ENABLED
TEST_CFLAGS=-fno-inline -fprofile-arcs -ftest-coverage
TEST_LFLAGS=-lgcov -coverage
else
TEST_CFLAGS=
TEST_LFLAGS=
endif

noinst_PROGRAMS = \
	bin/sanity \
	bin/bench \
	bin/sample_NTRUEncrypt

# Set conditionally below
TESTS =
check_PROGRAMS =
check_LTLIBRARIES =

noinst_LTLIBRARIES = libntrutests.la
lib_LTLIBRARIES = libntruencrypt.la

pkginclude_HEADERS = \
	include/ntru_crypto_error.h \
	include/ntru_crypto_platform.h \
	include/ntru_crypto_drbg.h \
	include/ntru_crypto.h

noinst_HEADERS = \
	src/ntru_crypto_hash_basics.h \
	src/ntru_crypto_hash.h \
	src/ntru_crypto_hmac.h \
	src/ntru_crypto_msbyte_uint32.h \
	src/ntru_crypto_ntru_convert.h \
	src/ntru_crypto_ntru_encrypt_key.h \
	src/ntru_crypto_ntru_encrypt_param_sets.h \
	src/ntru_crypto_ntru_mgf1.h \
	src/ntru_crypto_ntru_poly.h \
	src/ntru_crypto_sha1.h \
	src/ntru_crypto_sha256.h \
	src/ntru_crypto_sha2.h \
	src/ntru_crypto_sha.h \
	test/test_common.h \
	test/check_common.h

EXTRA_DIST = \
	autogen.sh \
	libntruencrypt.sym \
	src/ntru_crypto_ntru_mult_indices_32.c \
	src/ntru_crypto_ntru_mult_indices_64.c\
	doc \
	driver_test \
	vs2012

# libntruencrypt.la
libntruencrypt_la_CFLAGS = $(AM_CFLAGS) $(TEST_CFLAGS) -Wno-parentheses
libntruencrypt_la_LDFLAGS = \
	$(TEST_LFLAGS) \
	-version-info $(LIBNTRUENCRYPT_SO_VERSION) \
	-export-symbols $(top_srcdir)/libntruencrypt.sym
libntruencrypt_la_SOURCES = \
	src/ntru_crypto_drbg.c \
	src/ntru_crypto_hash.c \
	src/ntru_crypto_hmac.c \
	src/ntru_crypto_msbyte_uint32.c \
	src/ntru_crypto_ntru_convert.c \
	src/ntru_crypto_ntru_encrypt.c \
	src/ntru_crypto_ntru_encrypt_key.c \
	src/ntru_crypto_ntru_encrypt_param_sets.c \
	src/ntru_crypto_ntru_mgf1.c \
	src/ntru_crypto_ntru_poly.c \
	src/ntru_crypto_sha256.c \
	src/ntru_crypto_sha1.c \
	src/ntru_crypto_sha2.c
if SIMD_ENABLED
libntruencrypt_la_SOURCES += \
	src/ntru_crypto_ntru_mult_indices_simd.c \
	src/ntru_crypto_ntru_mult_coeffs_simd.c
libntruencrypt_la_CFLAGS += $(SIMD_FLAGS)
else
libntruencrypt_la_SOURCES += \
	src/ntru_crypto_ntru_mult_indices.c \
	src/ntru_crypto_ntru_mult_coeffs_karat.c
endif



# Test helper library
libntrutests_la_SOURCES = test/test_common.c

# If we have the CHECK package then link an extra copy of the library
# with all internal functions exposed and build unit tests.
if HAVE_CHECK
libntrutests_la_SOURCES += test/check_common.c

check_PROGRAMS += bin/check_public bin/check_internal

check_LTLIBRARIES += libntruencrypt_check.la
libntruencrypt_check_la_CFLAGS = $(libntruencrypt_la_CFLAGS)
libntruencrypt_check_la_LDFLAGS = $(TEST_LFLAGS)
libntruencrypt_check_la_SOURCES = $(libntruencrypt_la_SOURCES)
else
# If we don't have CHECK fall back to the basic sanity test
check_PROGRAMS += bin/sanity
endif

TESTS += $(check_PROGRAMS)


# Crude benchmarking program
bin_bench_SOURCES = test/bench.c
bin_bench_LDADD = \
	$(top_builddir)/libntruencrypt.la \
	$(top_builddir)/libntrutests.la

# Sample program
bin_sample_NTRUEncrypt_SOURCES = sample/sample_NTRUEncrypt.c
bin_sample_NTRUEncrypt_LDADD = libntruencrypt.la

# Sanity test for when CHECK package is not available
bin_sanity_SOURCES = test/sanity.c
bin_sanity_LDADD = \
	$(top_builddir)/libntruencrypt.la \
	$(top_builddir)/libntrutests.la

# Tests using only the public API
bin_check_public_SOURCES = test/check_public.c
bin_check_public_CFLAGS = $(AM_CFLAGS) @CHECK_CFLAGS@
bin_check_public_LDADD = \
	$(top_builddir)/libntruencrypt.la \
	$(top_builddir)/libntrutests.la \
	@CHECK_LIBS@

# Tests requiring access to internals
bin_check_internal_SOURCES = test/check_internal.c \
	test/check_internal_key.c \
	test/check_internal_poly.c \
	test/check_internal_sha.c \
	test/check_internal_mgf.c
bin_check_internal_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/src @CHECK_CFLAGS@
bin_check_internal_LDADD = \
	$(top_builddir)/libntruencrypt_check.la \
	$(top_builddir)/libntrutests.la \
	@CHECK_LIBS@


COVER_DIR=./coverage
coverage-html:
	test -d "$(COVER_DIR)" || mkdir -p "$(COVER_DIR)"
	lcov --rc lcov_branch_coverage=1 --directory ./src --zerocounters
	$(MAKE) check
	lcov --capture --rc lcov_branch_coverage=1 --no-external --directory . --output-file "$(COVER_DIR)/lcov.info"
	genhtml --branch-coverage -o "coverage" "$(COVER_DIR)/lcov.info"


mostlyclean-local:
	rm -f src/*.gc{da,no}
	test ! -d coverage || rm -rf coverage
