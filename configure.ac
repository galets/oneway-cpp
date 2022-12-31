AC_INIT([oneway], [0.2])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CXX
AC_CONFIG_FILES([Makefile])
AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_new], [], [AC_MSG_FAILURE([could not find OpenSSL])])
AC_OUTPUT
