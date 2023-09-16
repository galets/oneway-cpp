AC_INIT([oneway], [1.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])

LT_INIT

AC_PROG_CXX
AC_CHECK_PROG(LD, ld, ld, false)
if test "$LD" = "false"; then
  AC_MSG_ERROR([ld program not found])
fi

AC_CONFIG_MACRO_DIR([m4])
AX_CXX_COMPILE_STDCXX([17], [], [mandatory])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([src/config.h])

AC_OUTPUT
