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
