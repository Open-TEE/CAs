#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([CAs], [0.0.0], [https://github.com/Open-TEE/CAs/issues],
	[CAs], [https://github.com/Open-TEE])
AM_INIT_AUTOMAKE([dist-bzip2 foreign subdir-objects])
AC_CONFIG_SRCDIR([conn_test_app/conn_test_app.c])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
LT_INIT

# Ensure fuse available for omnishare
PKG_CHECK_MODULES(FUSE, fuse, , AC_MSG_ERROR('Unable to find libfuse.  Please make sure library and header files are installed.'))

AC_CHECK_HEADERS([fuse.h])

# Created configuration files
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
