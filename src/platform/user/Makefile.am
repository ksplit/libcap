
# Include all dirs for distribution/tarball
DIST_SUBDIRS = include src

# Include all dirs. Only include is really needed now for install.
SUBDIRS = include src

# User files. Note that we need to use absolute paths for
# includes because we're jumping back up the directory tree
# to compile common source.
USER_SRCS = \
	../../common/cap.c \
	../../common/cptr_cache.c \
	src/cap_user.c \
	src/cptr_cache_user.c
USER_INCLUDES = -I$(abs_top_srcdir)/src/platform/user/include

# Add includes to include search path
AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/src/include \
	-I$(abs_top_builddir)/src/include \
	$(USER_INCLUDES) \
	$(GLIB_INCLUDES)

# Build libcap as static lib
lib_LIBRARIES = libcap.a
libcap_a_SOURCES = $(USER_SRCS)
libcap_a_LIBADD = $(GLIB_LDFLAGS)
# automake hack so we can build both libs:
# (see: https://www.gnu.org/software/automake/manual/html_node/Objects-created-both-with-libtool-and-without.html)
libcap_a_CFLAGS = $(AM_CFLAGS) 

# Build libcap as shared lib using libtool
lib_LTLIBRARIES = libcap.la
libcap_la_SOURCES = $(USER_SRCS)
libcap_la_LIBADD = $(GLIB_LDFLAGS)
