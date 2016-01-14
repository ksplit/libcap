#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libcap], [0.1])
AS_INIT
AC_CONFIG_SRCDIR([src/common/cptr_cache.c])
AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_HEADERS([config.h])

LT_INIT
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([subdir-objects foreign])

# --------------------------------------------------
# Host check
# --------------------------------------------------

AC_CANONICAL_HOST

AC_MESSAGE_CHECKING([for OS X host])
AS_CASE($host

    [-*-*-darwin*]
    [
        AC_MESSAGE_RESULT([yes])
        AC_DEFINE(OS_DARWIN, 1, [Build for OS X host])
        AC_SUBST(OS_DARWIN)
    ])

# --------------------------------------------------
# libcap features and packages
# --------------------------------------------------

AC_ARG_ENABLE([user_lib],
    [AS_HELP_STRING([--disable-user-lib],
        [Disable user library build (default=no)])],
    [MAYBE_USER_LIB="user"],
    [MAYBE_USER_LIB=""])

AC_ARG_ENABLE([kernel_lib],
    [AS_HELP_STRING([--disable-kernel-lib],
        [Disable kernel library build (default=no)])],
    [MAYBE_KERNEL_LIB="kernel"],
    [MAYBE_KERNEL_LIB=""])

AS_IF([test "x$enable_kernel_lib" = "xyes"]

    [

        AC_ARG_ENABLE([kernel_module],
            [AS_HELP_STRING([--disable-kernel-module],
                [Disable kernel module build (default=no)])],
            [MAYBE_KERNEL_MODULE="module"],
            [MAYBE_KERNEL_MODULE=""])

    ])

# --------------------------------------------------
# Checks for programs.
# --------------------------------------------------

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_INSTALL

# --------------------------------------------------
# Checks for libraries.
# --------------------------------------------------

# Check for pthreads
AS_IF([test "x$enable_user_lib" = "xyes"],
    [AC_CHECK_LIB([pthread], [pthread_create])])

# Check glib (the gangsta lib)
AS_IF([test "x$enable_user_lib" = "xyes"],

    [
        GLIB=/usr # default prefix
        AC_ARG_WITH([glib],
            [AS_HELP_STRING([--with-glib=DIRECTORY],
                [find glib install in DIRECTORY])],
            [MAYBE_GLIB="$with_glib"])

        # Set up vars for the glib check
        old_CFLAGS=$CFLAGS
        old_LDFLAGS=$LDFLAGS
        GLIB_INCLUDES=`pkg-config --cflags $GLIB/lib/pkgconfig.pc`
        GLIB_LIBS=`pkg-config --libs $GLIB/lib/pkgconfig.pc`
        CFLAGS="${GLIB_INCLUDES} $CFLAGS"
        LDFLAGS="${GLIB_LIBS} $LDFLAGS"
    
        AC_CHECK_TYPE(gpointer,
            [],
            [AC_MSG_ERROR([Your glib includes seem wrong!])],
            [[#include <glib.h>]])

        AC_CHECK_LIB(glib-2.0,
            g_slice_alloc0,
            [],
            [AC_MSG_ERROR(Your glib does not have g_slice_alloc0; upgrade to 2.10+)])

        # Restore vars
        CFLAGS="$old_CFLAGS"
        LDFLAGS="$old_LDFLAGS"

        AC_SUBST(GLIB_INCLUDES)
        AC_SUBST(GLIB_LIBS)

    ])

# Check for kernel build system
AS_IF([test "x$enable_kernel_lib" = "xyes"],

    [
        KDIR=/lib/modules/`uname -r`/build # default location of build system

        AC_ARG_WITH([kernel-headers],
            [AS_HELP_STRING([--with-kernel-headers=DIRECTORY],
                [find Linux kernel build stuff in DIRECTORY])],
            [KDIR="$with_kernel"])

        # Sanity check it (in the future, we could maybe check the
        # kernel version in the top of the kernel Makefile)
        AC_CHECK_FILE($KDIR/Makefile,
            [AC_MSG_ERROR([Could not find kernel Makefile in $KDIR!])],
            [AC_MSG_NOTICE([Found kernel Makefile in $KDIR])])

    ])

# --------------------------------------------------
# Checks for header files.
# --------------------------------------------------

AC_CHECK_HEADERS([stdint.h stdlib.h string.h unistd.h])

# --------------------------------------------------
# Checks for types
# --------------------------------------------------

AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_CHECK_SIZEOF([unsigned long])

# --------------------------------------------------
# Checks for structures
# --------------------------------------------------

# --------------------------------------------------
# Checks for compiler characteristics
# --------------------------------------------------

AC_C_INLINE

# --------------------------------------------------
# Checks for library functions.
# --------------------------------------------------

AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup])

# --------------------------------------------------
# Config files
# --------------------------------------------------

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
