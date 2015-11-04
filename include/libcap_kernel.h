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

/**
 * Mutex support.
 */
typedef struct mutex cap_mutex_t;
static inline int __cap_mutex_init(cap_mutex_t *mutex)
{
	mutex_init(mutex);
	return 0;
}

static inline int __cap_mutex_lock(cap_mutex_t *mutex)
{
	mutex_lock(mutex);
	return 0;
}

static inline int __cap_mutex_trylock(cap_mutex_t *mutex)
{
	return !mutex_trylock(mutex);
}

static inline int __cap_mutex_lock_interruptible(cap_mutex_t *mutex)
{
	return mutex_lock_interruptible(mutex);
}

static inline int __cap_mutex_unlock(cap_mutex_t *mutex)
{
	mutex_unlock(mutex);
	return 0;
}

#endif /* __LIBCAP_KERNEL_H__ */
