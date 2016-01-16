#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

#include <libcap.h>

int cap_debug_level = 0;
module_param(cap_debug_level, int, 0644);
MODULE_PARM_DESC(cap_debug_level, "Debug level");

static int __init cap_init_module(void)
{
	cap_init();

	return 0;
}

static void __exit cap_fini_module(void)
{
	cap_fini();
	return;
}

module_init(cap_init_module);
module_exit(cap_fini_module);
MODULE_LICENSE("GPLv2");
