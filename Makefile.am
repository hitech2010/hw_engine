AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = README.md

pkglib_LTLIBRARIES = libhw_engine.la

libhw_engine_la_SOURCES = hw_engine.c hw_sha.c hw_sm1.c hw_sm234.c hw_aes.c hw_rsa.c hw_rand.c common.h

# Override some variables for the examples, this is NOT necessary
pkgdatadir = /usr/share/engine-zjw
pkgexecdir = /usr/share/engine-zjw/libexec
pkgincludedir = /usr/share/engine-zjw/include
pkglibdir = /usr/share/engine-zjw/lib
