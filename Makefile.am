SUBDIRS = .
ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = test_session
test_session_SOURCES = src/test_session.c
test_session_LDFLAGS = -ldl -lm -lcrypt
test_session_LDADD = ../libtee/lib_tee.la
AM_CPPFLAGS = -I../libtee/include
