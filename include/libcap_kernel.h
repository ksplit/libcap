#ifndef __LIBCAP_KERNEL_H__
#define __LIBCAP_KERNEL_H__

#include <linux/kernel.h>
#include <linux/sched.h>

CAP_BUILD_CORE_TYPES_NOBUILTIN();

#define __cap_err(format,...) \
    printk(KERN_ERR "cap: %s:%d: "format,__FUNCTION__,__LINE__,##__VA_ARGS__)
#define __cap_warn(format,...) \
    printk(KERN_WARNING "cap: %s:%d: "format,__FUNCTION__,__LINE__,##__VA_ARGS__)
#define __cap_msg(format,...) \
    printk(KERN_NOTICE "cap: %s:%d: "format,__FUNCTION__,__LINE__,##__VA_ARGS__)
#define __cap_debug(format,...) \
    printk(KERN_DEBUG,"cap: %s:%d: "format,__FUNCTION__,__LINE__,##__VA_ARGS__)

#endif /* __LIBCAP_KERNEL_H__ */
