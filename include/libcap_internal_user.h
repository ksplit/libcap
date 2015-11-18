#ifndef __LIBCAP_INTERNAL_USER_H__
#define __LIBCAP_INTERNAL_USER_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdarg.h>
#include <glib.h>
#include "libcap.h"
#include "libcap_types.h"
#include "list.h"
#include <string.h>
#include <errno.h>

#ifdef __APPLE__
#include "compat_internal/osx_user.h"
#endif

/**
 * Mutex support.  Follow kernel return convention.
 */
typedef pthread_mutex_t cap_mutex_t;
static inline int __cap_mutex_init(cap_mutex_t * mutex)
{
	return -pthread_mutex_init(mutex, NULL);
}

static inline int __cap_mutex_lock(cap_mutex_t * mutex)
{
	return -pthread_mutex_lock(mutex);
}

static inline int __cap_mutex_trylock(cap_mutex_t * mutex)
{
	return -pthread_mutex_trylock(mutex);
}

static inline int __cap_mutex_lock_interruptible(cap_mutex_t * mutex)
{
	return -pthread_mutex_lock(mutex);
}

static inline int __cap_mutex_unlock(cap_mutex_t * mutex)
{
	return -pthread_mutex_unlock(mutex);
}

/**
 * Cache support.
 */
struct cap_gslice_fakeslab {
	size_t size;
};
typedef struct cap_gslice_fakeslab cap_cache_t;
static inline cap_cache_t *__cap_gslice_fakeslab_create(size_t size)
{
	struct cap_gslice_fakeslab *gsfs;
	gsfs = malloc(sizeof(*gsfs));
	gsfs->size = size;
	return gsfs;
}

#define __cap_cache_create(__struct) __cap_gslice_fakeslab_create(sizeof(struct __struct))
#define __cap_cache_create2(__struct,name) __cap_gslice_fakeslab_create(sizeof(struct __struct))
static inline void __cap_cache_destroy(cap_cache_t * cache)
{
	/* Glib will just keep the pool around, I guess.  I assume it
	 * shrinks it periodically when g_slice_free1() is called.
	 */
	return;
}

static inline void *__cap_cache_alloc(cap_cache_t *cache)
{
	return g_slice_alloc0(cache->size);
}

static inline void *__cap_cache_zalloc(cap_cache_t *cache)
{
	return g_slice_alloc0(cache->size);
}

static inline void __cap_cache_free(cap_cache_t *cache, void *obj)
{
	g_slice_free1(cache->size, obj);
}



/**
 * Spinlocks.  An array of pthread spinlocks.  We have one for each L1
 * cache line.  This is stupid because glibc x86 pthread_spinlock_t is
 * an int, but we *hope* that pthreads is smarter about spinlocks than
 * we would be by ourselves (or than a straight userspace port of linux
 * atomic spin locks)... but after looking at the code I really don't
 * see that.  Oh well.
 */
extern pthread_spinlock_t *__spinlocks;
extern int __cache_lines;
extern int __cache_line_size;
extern int __l1_cache_size;

static inline pthread_spinlock_t *__addr_to_spinlock(void *addr)
{
	return __spinlocks +
	    ((((unsigned long)addr) / __cache_line_size) & (__cache_lines - 1));
}

static inline void __cap_atomic_spin_lock(void *addr)
{
	pthread_spin_lock(__addr_to_spinlock(addr));
}

static inline __cap_atomic_spin_unlock(void *addr)
{
	pthread_spin_unlock(__addr_to_spinlock(addr));
}

#ifndef __WORDSIZE
#define __WORDSIZE (sizeof(long) * 8)
#endif

#define BITS_PER_LONG __WORDSIZE

#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE           8

static inline void __cap_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long flags;

	__cap_atomic_spin_lock(p);
	*p |= mask;
	__cap_atomic_spin_unlock(p);
}

static inline void __cap_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long flags;

	__cap_atomic_spin_lock(p);
	*p &= ~mask;
	__cap_atomic_spin_unlock(p);
}

/**
 * Memory.
 */
#define __cap_zalloc(nmemb,size) calloc((nmemb),(size))
#define __cap_free(addr) free(addr)

#define msleep(ms) usleep(10 * (ms))
#define BUG_ON(cond) assert(!(cond))

#ifndef __WORDSIZE
#define __WORDSIZE (sizeof(long) * 8)
#endif

#define BITS_PER_LONG __WORDSIZE

#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE           8
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITS_TO_U64(nr)         DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(u64))
#define BITS_TO_U32(nr)         DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(u32))
#define BITS_TO_BYTES(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE)

#ifndef min
#define min(x, y) ({                            \
        typeof(x) _min1 = (x);                  \
        typeof(y) _min2 = (y);                  \
        (void) (&_min1 == &_min2);              \
        _min1 < _min2 ? _min1 : _min2; })
#endif

static inline unsigned long ffz(unsigned long word)
{
 asm("rep; bsf %1,%0":"=r"(word)
 :	    "r"(~word));
	return word;
}

static unsigned long find_first_zero_bit(const unsigned long *addr,
					 unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx] != ~0UL)
			return min(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}

	return size;
}

#endif /* __LIBCAP_INTERNAL_USER_H__ */
