AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = README.md

pkglib_LTLIBRARIES = libhw_engine.la

libhw_engine_la_SOURCES = hw_engine.c hw_md5.c

# Override some variables for the examples, this is NOT necessary
pkgdatadir = /usr/share/engine-zjw
pkgexecdir = /usr/share/engine-zjw/libexec
pkgincludedir = /usr/share/engine-zjw/include
pkglibdir = /usr/share/engine-zjw/lib
