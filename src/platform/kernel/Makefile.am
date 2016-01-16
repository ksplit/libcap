
# Include all dirs for distribution/tarball
DIST_SUBDIRS = include src module test

# Recurse into all for install/dist targets
SUBDIRS = include src module test

# Kernel files
KERNEL_INCLUDES = -I$(abs_top_srcdir)/src/platform/kernel/include

# Add includes to include search path
AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/src/include \
	-I$(abs_top_builddir)/src/include \
	$(KERNEL_INCLUDES) \
	$(GLIB_INCLUDES)

COMMON_SRCS = \
	../../common/cap.c \
	../../common/cptr_cache.c

export AM_CPPFLAGS COMMON_SRCS

LIBCAP_KBUILD=$(PWD)
LIBCAP_KERNEL_MODULE_KBUILD=$(PWD)/module

# Automake if's aren't as powerful as GNU Make's (partly since Automake
# doesn't know the config selections when it does its job)
if ENABLE_KERNEL_MODULE

MAYBE_ALL_MODULE = all-module
MAYBE_CLEAN_MODULE = clean-module
MAYBE_MODULES_INSTALL = do-modules-install

endif

# TODO: Add kernel tests
if ENABLE_TEST_BUILD

endif

# Sequence the build, so we build the lib first
all: all-lib-cp $(MAYBE_ALL_MODULE)

all-module: all-lib-cp
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) modules

all-lib-cp: all-lib
	cp lib.a libcap.a

all-lib:
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KBUILD)

install-headers:
	@echo "Installing libcap kernel headers to $(KERNEL_HEADERS_INSTALL)..."
	mkdir -p $(KERNEL_HEADERS_INSTALL)
	cp $(top_srcdir)/src/platform/kernel/include/libcap_platform.h $(KERNEL_HEADERS_INSTALL)
	cp $(top_srcdir)/src/platform/kernel/include/libcap_platform_types.h $(KERNEL_HEADERS_INSTALL)
	cp $(top_srcdir)/src/include/libcap.h $(KERNEL_HEADERS_INSTALL)
	cp $(top_builddir)/src/include/libcap_config.h $(KERNEL_HEADERS_INSTALL)
	cp $(top_srcdir)/src/include/libcap_types.h $(KERNEL_HEADERS_INSTALL)
	cp $(top_srcdir)/src/include/libcap_list.h $(KERNEL_HEADERS_INSTALL)

uninstall-headers:
	@echo "Uninstalling libcap kernel headers from $(KERNEL_HEADERS_INSTALL)..."
	rm -f $(KERNEL_HEADERS_INSTALL)/libcap_platform.h
	rm -f $(KERNEL_HEADERS_INSTALL)/libcap_platform_types.h
	rm -f $(KERNEL_HEADERS_INSTALL)/libcap.h
	rm -f $(KERNEL_HEADERS_INSTALL)/libcap_config.h
	rm -f $(KERNEL_HEADERS_INSTALL)/libcap_types.h
	rm -f $(KERNEL_HEADERS_INSTALL)/libcap_list.h

# Don't do regular install; user probably doesn't want kernel stuff in
# user-level directories.
install: install-headers
	@echo ""; \
	echo "----------------------------------------"; \
	echo "             NOTE"; \
	echo ""; \
	echo "We only install the kernel headers (according to the"; \
	echo "KERNEL_HEADERS_INSTALL variable). You probably don't want"; \
	echo "e.g. kernel headers mixed up in your user include directories"; \
	echo "and stuff. You can find libcap.a and libcap.ko in"; \
	echo "(libcap build dir)/src/platform/kernel."; \
	echo "To install the kernel module, do 'make modules_install'"; \
	echo "in the root of the libcap build tree."; \
	echo ""; \
	echo "----------------------------------------"

uninstall: uninstall-headers
	@echo "----------------------------------------"; \
	echo "             NOTE"; \
	echo ""; \
	echo "Skipping uninstall of libcap.a and libcap.ko."; \
	echo "If you installed the libcap.ko kernel module via"; \
	echo "modules_install (in the root of the libcap build tree)"; \
	echo "then there really isn't an easy way (that I know of) to"; \
	echo "remove the kernel module. It was installed somewhere in"; \
	echo '  /lib/modules/`uname -r`/build'; \
	echo "(or something similar)."; \
	echo "You will have to manually remove it."; \
	echo ""; \
	echo "----------------------------------------"


do-modules-install:
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) \
		modules_install

modules_install: $(MAYBE_MODULES_INSTALL)

clean: clean-lib $(MAYBE_CLEAN_MODULE)

clean-module:
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) clean

clean-lib:
	$(MAKE) -C $(KDIR) M=$(LIBCAP_KBUILD) clean
	rm -f libcap.a

.PHONY: all-module all-lib all-lib-cp do-modules-install modules_install \
	clean-module clean-lib install-headers uninstall-headers
