
noinst_PROGRAMS = cap-stuff multi_thrd_cap

noinst_HEADERS = \
	$(top_srcdir)/include/libcap.h $(top_srcdir)/include/libcap_types.h \
	$(top_srcdir)/include/libcap_user.h

AM_CPPFLAGS = -I$(top_srcdir)/include $(GLIB_INCLUDES)

LDADD = ../../src/user/libcap.la $(GLIB_LDFLAGS)
#
# I suppose this kind of interferes with standard libtool practice, but this
# is what I use to ensure the test executables are linked statically against the
# libcap libs.  If you want them to be dynamically linked, set this var empty.
#
AM_LDFLAGS =  -static-libtool-libs
