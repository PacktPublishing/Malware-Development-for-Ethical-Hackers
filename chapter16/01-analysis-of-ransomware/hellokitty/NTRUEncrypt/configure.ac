AC_PREREQ([2.69])
AC_INIT([libntruencrypt],[1.1.0])
AC_CONFIG_SRCDIR([src/ntru_crypto_drbg.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

dnl autoscan: Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h unistd.h])

dnl autoscan: Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT16_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

dnl autoscan: Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove memset])

dnl Need check for unit tests
PKG_CHECK_MODULES([CHECK], [check >= 0.9.6], [have_check=yes], [have_check=no])
AM_CONDITIONAL(HAVE_CHECK, test "x$have_check" = "xyes")

dnl Compute the canonical host-system type variable, host, and its three individual
dnl parts host_cpu, host_vendor, and host_os.
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT

# Using libtool library versioning, current:revision:age
# http://gnu.org/software/libtool/manual/html_node/Updating-version-info.html
LIBNTRUENCRYPT_SO_VERSION=1:0:1
AC_SUBST([LIBNTRUENCRYPT_SO_VERSION])

dnl Suggest -O3 without debugging symbols if there are no user-specified CFLAGS
if test "x$CFLAGS" = "x"; then
  CFLAGS=-O3
fi
AC_PROG_CC

AC_ARG_ENABLE(simd,
   AS_HELP_STRING([--enable-simd],
                  [Enable vectorized polynomial arithmetic (default=no)]),
                  [], [enable_simd=no])
AC_ARG_ENABLE(coverage,
   AS_HELP_STRING(--enable-coverage, [Enable coverage reporting for tests]))


if test "x$enable_simd" = "xyes"; then
  AX_EXT
fi
AM_CONDITIONAL(SIMD_ENABLED,\
               test x$enable_simd == xyes && test x$ax_cv_have_ssse3_ext == xyes)

AM_CONDITIONAL(COVERAGE_ENABLED, test x$enable_coverage = xyes)


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
