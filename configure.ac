AC_INIT([oneway], [1.0])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CXX
AC_CONFIG_MACRO_DIR([m4])
AX_CXX_COMPILE_STDCXX([20], [], [mandatory])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])


# Check for C++ compiler and set CXXFLAGS
AC_PROG_CXX

AC_CHECK_LIB([cryptopp], [],
    [LIBS="-Lexternal/cryptopp -lcryptopp"], [AC_MSG_ERROR([Crypto++ library not found])])

AC_MSG_CHECKING([for cryptopp library])
AC_CONFIG_COMMANDS([cryptopp], [cp external/cryptopp-pem/* external/cryptopp/ && cd external/cryptopp && $(MAKE)],
    [AC_MSG_ERROR([Failed to build dependent library])])
AC_MSG_RESULT([found])])


AC_ARG_WITH([cryptopp],
    [AS_HELP_STRING([--with-cryptopp=DIR], [Specify location of cryptopp source directory])])
AS_IF([test "x$with_cryptopp" != "x"],
    [AC_MSG_CHECKING([for cryptopp source code])
     AC_CONFIG_SUBDIRS([$with_cryptopp])
     AC_MSG_RESULT([found])
     LIBS="-Lexternal/library -lcryptopp"
     AC_MSG_CHECKING([for cryptopp library])
     AC_CONFIG_COMMANDS([cryptopp], [cp external/cryptopp-pem/* external/cryptopp/ && cd external/cryptopp && $(MAKE)],
         [AC_MSG_ERROR([Failed to build dependent library])])
     AC_MSG_RESULT([found])])

AC_OUTPUT
