#ifndef __LIBCAP_INTERNAL_KERNEL_H__
#define __LIBCAP_INTERNAL_KERNEL_H__

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/string.h>
#include "libcap_types.h"

#define strdup(str) kstrdup(str,GFP_KERNEL)

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

/**
 * Cache support.
 */
typedef struct kmem_cache cap_cache_t;
#define __cap_cache_create(__struct)					\
    kmem_cache_create(#__struct,					\
		      sizeof(struct __struct), __alignof__(struct __struct), \
		      0, NULL)
#define __cap_cache_create2(__struct,name) kmem_cache_create((name),sizeof(struct __struct),__alignof__(struct __struct),0,NULL)
static inline void *__cap_cache_alloc(cap_cache_t *cache)
{
	return kmem_cache_alloc(cache, 0);
}

static inline void *__cap_cache_zalloc(cap_cache_t *cache)
{
	return kmem_cache_zalloc(cache, 0);
}

static inline void __cap_cache_destroy(cap_cache_t *cache)
{
	kmem_cache_destroy(cache);
}

static inline void __cap_cache_free(cap_cache_t *cache, void *obj)
{
	kmem_cache_free(cache, obj);
}

/**
 * Spinlock macros.
 */
#define __cap_set_bit set_bit
#define __cap_clear_bit clear_bit

/**
 * Memory.
 */
#define __cap_zalloc(nmemb,size) kzalloc((nmemb)*(size),GFP_KERNEL)
#define __cap_free(addr) kfree(addr)

#define __cptr_init()
#define __cptr_fini()

#endif /* __LIBCAP_INTERNAL_KERNEL_H__ */
