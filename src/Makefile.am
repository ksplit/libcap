
DIST_SUBDIRS = common include platform
COMMON_SRCS = common/cap.o common/cptr_cache.o
COMMON_INCLUDES = -Iinclude

include platform/$(PLATFORM)/top_level.am



###############

ifeq ($(PLATFORM),kernel)

lib_LIBRARIES = libcap.a
libcap_a_SOURCES = cap.o cptr_cache.o

else ifeq($(PLATFORM),user)

lib_LIBRARIES = libcap.a
AM_CPPFLAGS = -I$(top_srcdir)/include $(GLIB_INCLUDES)
lib_LTLIBRARIES = libcap.la
libcap_la_LIBADD = $(GLIB_LDFLAGS)
noinst_HEADERS = \
	$(top_srcdir)/include/libcap.h $(top_srcdir)/include/libcap_types.h \
	$(top_srcdir)/include/libcap_user.h \
	$(top_srcdir)/include/libcap_internal.h \
	$(top_srcdir)/include/libcap_internal_user.h $(top_srcdir)/include/list.h 
#
# The fact that this works is probably deceptive.  Autofoo puts the .deps stuff
# for the common files in the common dir.  The reason that works is because our
# only other "platform" is the kernel, which uses kernel-fu instead of autofoo.
#
libcap_la_SOURCES = \
	../common/cap.c ../common/cptr_cache.c \
	cap_user.c cptr_cache_user.c


endif

SUBDIRS = common platform include
