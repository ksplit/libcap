
# Include all dirs for distribution/tarball
DIST_SUBDIRS = include src module

# Include all dirs. Only include is really needed now for install.
SUBDIRS = include src module

# Kernel files
KERNEL_INCLUDES = -I$(abs_top_srcdir)/src/platform/kernel/include

# Add includes to include search path
AM_CPPFLAGS = \
	-I$(abs_top_srcdir)/src/include \
	-I$(abs_top_builddir)/src/include \
	$(KERNEL_INCLUDES) \
	$(GLIB_INCLUDES)

COMMON_SRCS = \
	../common/cap.c \
	../common/cptr_cache.c

export AM_CPPFLAGS COMMON_SRCS

LIBCAP_KBUILD=$(PWD)
LIBCAP_KERNEL_MODULE_KBUILD=$(PWD)/platform/kernel/module

# Automake if's aren't as powerful as GNU Make's (partly since Automake
# doesn't know the config selections when it does its job)
all_cmd = $(MAKE) -C $(KDIR) M=$(LIBCAP_KBUILD) \
	CPPFLAGS="$(AM_CPPFLAGS) $(CPPFLAGS)" modules
install_cmd = $(MAKE) -C $(KDIR) M=$(LIBCAP_KBUILD) modules_install
clean_cmd = $(MAKE) -C $(KDIR) M=$(LIBCAP_KBUILD) clean

if ENABLE_KERNEL_MODULE

all_cmd += ; $(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) \
	CPPFLAGS="$(AM_CPPFLAGS) $(CPPFLAGS)" modules
install_cmd += ; $(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) \
	modules_install
clean_cmd += ; $(MAKE) -C $(KDIR) M=$(LIBCAP_KERNEL_MODULE_KBUILD) clean

endif

all:
	$(all_cmd)

install:
	$(install_cmd)

clean:
	$(clean_cmd)
