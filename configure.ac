#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libcap], [0.1])
AC_CONFIG_SRCDIR([src/common/cptr_cache.c])
AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_HEADERS([config.h])

LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([subdir-objects foreign])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_INSTALL

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [pthread_create])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup])

# Check size of unsigned long (determines cspace sizing, cptr ABI, and so on)
AC_CHECK_SIZEOF([unsigned long])

#
# Check glib.
#
GLIB=/usr
AC_ARG_WITH([glib],
  AS_HELP_STRING([--with-glib=DIRECTORY],
    [find glib install in DIRECTORY]),
  [GLIB="$with_glib"])
if test ! "$GLIB" = "/usr" ; then
    old_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
    export PKG_CONFIG_PATH="$GLIB/lib/pkgconfig"
fi
old_CFLAGS=$CFLAGS
old_LDFLAGS=$LDFLAGS
GLIB_INCLUDES=`pkg-config --cflags glib-2.0`
GLIB_LIBS=`pkg-config --libs glib-2.0`
CFLAGS="${GLIB_INCLUDES} $CFLAGS"
LDFLAGS="${GLIB_LIBS} $LDFLAGS"
AC_CHECK_TYPE(gpointer,
    [],
    [AC_MSG_ERROR([Your glib includes seem wrong!])],
    [[#include <glib.h>]])
AC_CHECK_LIB(glib-2.0,g_slice_alloc0,[],[AC_MSG_ERROR(Your glib does not have g_slice_alloc0; upgrade to 2.10+)])
if test ! "$GLIB" = "/usr" ; then
    export PKG_CONFIG_PATH="$old_PKG_CONFIG_PATH"
fi
CFLAGS="$old_CFLAGS"
LDFLAGS="$old_LDFLAGS"
AC_SUBST(GLIB_INCLUDES)
AC_SUBST(GLIB_LIBS)

#
# Check kernel
#
if test "x$KDIR" = "x" ; then
   KDIR=/lib/modules/`uname -r`/build
fi
AC_ARG_WITH([kernel],
  AS_HELP_STRING([--with-kernel=DIRECTORY],
    [find Linux kernel build stuff in DIRECTORY]),
  [KDIR="$with_kernel"])
AC_ARG_ENABLE(kernel,
	      AS_HELP_STRING([--disable-kernel],
                             [Disable kernel module build and test]))
if test "x$enableval" = "xno"; then
    ENABLE_KERNEL=0;
    MAYBE_KERNEL=
else
    ENABLE_KERNEL=1;
    MAYBE_KERNEL=kernel
fi
AC_SUBST(ENABLE_KERNEL)
AC_SUBST(MAYBE_KERNEL)
if test ${ENABLE_KERNEL} -eq 1 ; then
    if test ! -f $KDIR/Makefile ; then
        AC_MSG_ERROR([Could not find kernel Makefile in $KDIR!])
    else
        AC_MSG_NOTICE([Found kernel Makefile in $KDIR])
    fi
fi

if test ${ENABLE_KERNEL} -eq 1 ; then
    #
    # This is pretty horrible, but I can't find a way to tell the kernel
    # build that 1) Makefile is in the object tree (the output dir); and 2)
    # the sources are in the source tree.  The kernel expects the Makefile
    # to be with the sources.  So, ugh, but oh well.
    #
    AC_CONFIG_LINKS([src/kernel/cap.c:src/common/cap.c
                     src/kernel/cptr_cache.c:src/common/cptr_cache.c
                     src/kernel/cap_module.c:src/kernel/cap_module.c])
fi

AC_CONFIG_FILES(
  Makefile
  include/Makefile
  src/Makefile
  src/user/Makefile
  src/kernel/Makefile
  test/Makefile
  test/user/Makefile
  test/kernel/Makefile
)
AC_OUTPUT
