#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([Open-TEE], [1.0], [open-tee@googlegroups.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/test_session.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

# Checks for libraries.
LT_INIT

# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([memset socket strerror])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
