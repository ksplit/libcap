
# Include all dirs for distribution/tarball
DIST_SUBDIRS = include src module test

# Recurse into all for install/dist targets
SUBDIRS = include src module test

# Kernel files
KERNEL_INCLUDES = -I$(abs_top_srcdir)/src/platform/kernel/include

# Add includes to include search path. (The root of the builddir is necessary to
# add explicitly for the kernel build, because we pass the include paths to the kernel
# build system. It won't check in the root of the build dir unless we tell it to.)
AM_CPPFLAGS = \
	-I$(abs_top_builddir) \
	-I$(abs_top_srcdir)/src/include \
	-I$(abs_top_builddir)/src/include \
	$(KERNEL_INCLUDES) \
	$(GLIB_INCLUDES)

COMMON_SRCS = \
	common/cap.c \
	common/cptr_cache.c \
	common/type_system.c

export AM_CPPFLAGS COMMON_SRCS

LIBCAP_KBUILD=@abs_top_builddir@/src
LIBCAP_KERNEL_MODULE_KBUILD=$(PWD)/module

# Automake if's aren't as powerful as GNU Make's (partly since Automake
# doesn't know the config selections when it does its job)
if ENABLE_KERNEL_MODULE

MAYBE_ALL_MODULE = all-module
MAYBE_CLEAN_MODULE = clean-module
MAYBE_MODULES_INSTALL = do-modules-install
MAYBE_INSTALL_MODULE = install-libcap-module

endif

# TODO: Add kernel tests
if ENABLE_TEST_BUILD

endif

# Sequence the build, so we build the lib first
all: all-lib-cp $(MAYBE_ALL_MODULE)

all-module: all-lib-cp
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) modules

all-lib-cp: all-lib
	cp $(LIBCAP_KBUILD)/lib.a $(LIBCAP_KBUILD)/libcap.a

all-lib:
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KBUILD)

# Move libcap.a and libcap.ko into dest dir. Easier to chain with
# multiple targets (esp. since we may not have built the module)
install-exec-hook: install-libcap $(MAYBE_INSTALL_MODULE)

install-libcap-module: install-setup-dir
	cp module/libcap.ko $(DESTDIR)$(libdir)

install-libcap: install-setup-dir
	cp $(LIBCAP_KBUILD)/libcap.a $(DESTDIR)$(libdir)

install-setup-dir:
	$(MKDIR_P) $(DESTDIR)$(libdir)

do-modules-install:
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) \
		modules_install

modules_install: $(MAYBE_MODULES_INSTALL)

clean: clean-lib $(MAYBE_CLEAN_MODULE)

clean-module:
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) clean

clean-lib:
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KBUILD) clean
	rm -f $(LIBCAP_KBUILD)/libcap.a

.PHONY: all-module all-lib all-lib-cp do-modules-install modules_install \
	clean-module clean-lib install-headers uninstall-headers \
	install-libcap-module install-libcap install-setup-dir
