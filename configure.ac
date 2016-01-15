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

# --------------------------------------------------
# Host check
# --------------------------------------------------

AC_CANONICAL_HOST

AC_MSG_CHECKING([for OS X host])
AS_CASE([$host],

    [-*-*-darwin*],
    [
        AC_MSG_RESULT([yes])
        AC_DEFINE(CAP_OS_DARWIN, 1, [Build for OS X host])
        AC_SUBST(CAP_OS_DARWIN)
    ],

    [*],
    [
        AC_MSG_RESULT([no])
    ])


# --------------------------------------------------
# libcap features, packages, and config
# --------------------------------------------------

# Platform = user xor kernel
AC_ARG_VAR([PLATFORM],
    [The platform to build for @{:@user|kernel@:}@ (default=user)])
AS_CASE([$PLATFORM],
    [user],
    [PLATFORM_DIR=platform/user],
    [kernel],
    [PLATFORM_DIR=platform/kernel],
    [*],
    [
        AC_MSG_NOTICE([PLATFORM (val=$PLATFORM) unset or invalid.])
        AC_MSG_NOTICE([Defaulting to PLATFORM=user.])
        PLATFORM=user
        PLATFORM_DIR=platform/user
    ])
AC_MSG_NOTICE([Building for PLATFORM=$PLATFORM.])
AC_SUBST(PLATFORM)
AC_SUBST(PLATFORM_DIR)

# CSpace depth. We use bits to enforce that the depth is a power of 2.
AC_ARG_VAR([CSPACE_DEPTH_BITS],
    [Set CSPACE depth to 2^CSPACE_DEPTH_BITS (default=2, default depth=4)])
AS_IF([test "x$CSPACE_DEPTH_BITS" = "x"],
    [CSPACE_DEPTH_BITS="2"]) # default
AS_CASE([$CSPACE_DEPTH_BITS],

    [@<:@0-8@:>@],
    [CAP_CSPACE_DEPTH_BITS=$CSPACE_DEPTH_BITS],

    [*],
    [
        AC_MSG_ERROR([CSpace depth bits (val=$CSPACE_DEPTH_BITS) invalid. Please choose a value between 0 and 8.])
    ])
AC_MSG_NOTICE([CSpace depth bits = $CAP_CSPACE_DEPTH_BITS.])
AC_SUBST(CAP_CSPACE_DEPTH_BITS)

# CNode table size. Again, we use bits to enforce that it's a power of 2.
AC_ARG_VAR([CSPACE_CNODE_TABLE_BITS],
    [CNode tables have 2^CSPACE_CNODE_TABLE_BITS total slots (default=6, default size=64)])
AS_IF([test "x$CSPACE_CNODE_TABLE_BITS" = "x"],
    [CSPACE_CNODE_TABLE_BITS="6"]) # default
AS_CASE([$CSPACE_CNODE_TABLE_BITS],

    [@<:@1-9@:>@],
    [CAP_CSPACE_CNODE_TABLE_BITS=$CSPACE_CNODE_TABLE_BITS],

    [*],
    [
        AC_MSG_ERROR([CSpace cnode table bits (val=$CSPACE_CNODE_TABLE_BITS) invalid. Please choose a value between 1 and 9.])
    ])
AC_MSG_NOTICE([CNode table bits = $CAP_CSPACE_CNODE_TABLE_BITS.])
AC_SUBST(CAP_CSPACE_CNODE_TABLE_BITS)

# Kernel module build?
AS_IF([test "x$PLATFORM" = "xkernel"],

    [
        # Build libcap as kernel module, in addition to static lib.a
        AC_ARG_ENABLE([kernel_module],
            [AS_HELP_STRING([--disable-kernel-module],
                [Disable kernel module build (default=no)])])
        AM_CONDITIONAL(ENABLE_KERNEL_MODULE, 
            [test "x$enable_kernel_module" = "xyes"])

    ],

    [

        AM_CONDITIONAL(ENABLE_KERNEL_MODULE, 
            [false])

    ])

AC_ARG_ENABLE([test_build],
    [AS_HELP_STRING([--disable-test-build],
        [Disable building test applications (default=no)])])
AM_CONDITIONAL(ENABLE_TEST_BUILD, 
    [test "x$enable_test_build" = "xyes"])

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
AC_PROG_AWK # for a calculation below

# --------------------------------------------------
# Checks for libraries.
# --------------------------------------------------

# Check for pthreads
AS_IF([test "x$PLATFORM" = "xuser"],
    [AC_CHECK_LIB([pthread], [pthread_create])])

# Check glib (the gangsta lib)
AS_IF([test "x$PLATFORM" = "xuser"],

    [
        GLIB=/usr # default prefix
        AC_ARG_WITH([glib],
            [AS_HELP_STRING([--with-glib=DIRECTORY],
                [find glib install in DIRECTORY])],
            [MAYBE_GLIB="$with_glib"])

        # Set up vars for the glib check
        old_CFLAGS=$CFLAGS
        old_LDFLAGS=$LDFLAGS
        old_PKG_CONFIG_PATH=$PKG_CONFIG_PATH

        # (It's tricky to try to locate the .pc file, so we don't
        # try to do the absolute path with the call to pkg-config)
        GLIB_INCLUDES=`pkg-config --cflags glib-2.0`
        GLIB_LIBS=`pkg-config --libs glib-2.0`
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
        PKG_CONFIG_PATH="$old_PKG_CONFIG_PATH"

        AC_SUBST(GLIB_INCLUDES)
        AC_SUBST(GLIB_LIBS)

    ])

# Check for kernel build system
AS_IF([test "x$PLATFORM" = "xkernel"],

    [
        KDIR=/lib/modules/`uname -r`/build # default location of build system

        AC_ARG_WITH([kernel-headers],
            [AS_HELP_STRING([--with-kernel-headers=DIRECTORY],
                [find Linux kernel build stuff in DIRECTORY])],
            [KDIR="$with_kernel_headers"])

        # Sanity check it (in the future, we could maybe check the
        # kernel version in the top of the kernel Makefile)
        AC_CHECK_FILE($KDIR/Makefile,
            [AC_MSG_NOTICE([Found kernel Makefile in $KDIR])],
            [AC_MSG_ERROR([Could not find kernel Makefile in $KDIR!])])


        AC_SUBST(KDIR)

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

# Sanity check cspace depth and cnode table size, now that we
# have the size of an unsigned long.
AC_MSG_CHECKING([that cspace config is sane])
cptr_size=`$AWK "BEGIN { print (2 ** $CAP_CSPACE_DEPTH_BITS) * ($CAP_CSPACE_CNODE_TABLE_BITS - 1) + $CAP_CSPACE_DEPTH_BITS }"`
long_size=`$AWK "BEGIN { print $ac_cv_sizeof_unsigned_long * 8 }"`
AS_IF([test "$cptr_size" -gt "$long_size"],
    [
        AC_MSG_RESULT([no])
        AC_MSG_NOTICE([The cspace configuration you chose won't work.])
        AC_MSG_NOTICE([Your choice must fulfill this:])
        AC_MSG_NOTICE([  let a = 2^cspace depth bits])
        AC_MSG_NOTICE([  let b = a * (table bits - 1) + cspace depth bits])
        AC_MSG_NOTICE([  let c = bits in an unsigned long])
        AC_MSG_NOTICE([  require: b <= c])
        AC_MSG_NOTICE([(This has to do with packing bits into an unsigned long for cptr's.)])
        AC_MSG_NOTICE([FYI - The default (depth bits = 2, table bits = 6) should work on 64- and 32-bit.])
        AC_MSG_ERROR([Please re-configure with different cspace settings.])
    ])
AC_MSG_RESULT([yes])

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

  src/Makefile
  src/common/Makefile

  src/include/Makefile
  src/include/libcap_config.h

  src/platform/Makefile
  src/platform/kernel/Makefile
  src/platform/kernel/src/Makefile
  src/platform/kernel/module/Kbuild:src/platform/kernel/module/Kbuild.in
  src/platform/Kbuild:src/platform/kernel/Kbuild.in
  src/platform/kernel/include/Makefile

  src/platform/user/Makefile
  src/platform/user/src/Makefile
  src/platform/user/include/Makefile

  test/Makefile
  test/user/Makefile
  test/kernel/Makefile
)
AC_OUTPUT

