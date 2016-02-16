AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = README.md rfc1321/global.h rfc1321/md5.h

pkglib_LTLIBRARIES = libemd5.la

libemd5_la_SOURCES = e_md5.c rfc1321/md5c.c

# Override some variables for the examples, this is NOT necessary
pkgdatadir = /usr/share/engine-zjw
pkgexecdir = /usr/share/engine-zjw/libexec
pkgincludedir = /usr/share/engine-zjw/include
pkglibdir = /usr/share/engine-zjw/lib
