/*
 * libcap_platform.h
 *
 * Kernel-specific implementations of cap functions.
 *
 * Copyright: University of Utah
 */
#ifndef __LIBCAP_PLATFORM_H__
#define __LIBCAP_PLATFORM_H__

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/bug.h>

#define __cap_err(format,...) \
    printk(KERN_ERR "cap: %s:%d: "format,__FUNCTION__,__LINE__,##__VA_ARGS__)
#define __cap_warn(format,...) \
    printk(KERN_WARNING "cap: %s:%d: "format,__FUNCTION__,__LINE__,##__VA_ARGS__)
#define __cap_msg(format,...) \
    printk(KERN_NOTICE "cap: %s:%d: "format,__FUNCTION__,__LINE__,##__VA_ARGS__)
#define __cap_debug(format,...) \
    printk(KERN_DEBUG,"cap: %s:%d: "format,__FUNCTION__,__LINE__,##__VA_ARGS__)

#define __cap_bug() BUG()

#define __cap_bug_on(cond) BUG_ON(cond)

#endif /* __LIBCAP_PLATFORM_H__ */
