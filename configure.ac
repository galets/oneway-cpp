AC_INIT([oneway], [0.2])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CXX
AC_CONFIG_MACRO_DIR([m4])
AX_CXX_COMPILE_STDCXX([20], [], [mandatory])
AC_CONFIG_FILES([Makefile])
AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_new], [], [AC_MSG_FAILURE([could not find OpenSSL])])
AC_OUTPUT
