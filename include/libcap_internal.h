#ifndef __LIBCAP_INTERNAL_H__
#define __LIBCAP_INTERNAL_H__

#include "libcap_types.h"

struct cnode;
struct cdt_root_node;
struct cspace;
struct cnode_table;

enum allocation_state {
	ALLOCATION_INVALID,
	ALLOCATION_VALID,
	ALLOCATION_MARKED_FOR_DELETE,
	ALLOCATION_REMOVED,
};

#ifdef __KERNEL__
#include "libcap_internal_kernel.h"
#else
#include "libcap_internal_user.h"
#endif

struct cnode {
	cptr_t cptr;
	cap_mutex_t lock;
	/*
	 * cnode data
	 */
	cap_type_t type;
	void *object;
	struct cspace *cspace;
	/*
	 * cdt data
	 */
	struct cdt_root_node *cdt_root;
	struct list_head children;
	struct list_head siblings;
};

struct cnode_table {
	struct cnode cnode[CAP_CSPACE_CNODE_TABLE_SIZE];
	uint8_t table_level;
	struct list_head table_list;
};

struct cspace {
	void *owner;
	cap_mutex_t lock;
	enum allocation_state state;
	struct cnode_table *cnode_table;
	cap_cache_t *cnode_table_cache;
	struct list_head table_list;
};

struct cdt_root_node {
	cap_mutex_t lock;
	struct cnode *cnode;
	enum allocation_state state;
};

/* The init and finish routines are defined in their own compoents. The
 * implementations differ between the kernel and userspace. */
int __cptr_init(void);
void __cptr_fini(void);

/**
 * Generic mutex wrappers.  Defined by platform-specific code.
 */
static inline int cap_mutex_init(cap_mutex_t *mutex)
{
	return __cap_mutex_init(mutex);
}

static inline int cap_mutex_lock(cap_mutex_t *mutex)
{
	return __cap_mutex_lock(mutex);
}

static inline int cap_mutex_trylock(cap_mutex_t *mutex)
{
	return __cap_mutex_trylock(mutex);
}

static inline int cap_mutex_lock_interruptible(cap_mutex_t *mutex)
{
	return __cap_mutex_lock_interruptible(mutex);
}

static inline int cap_mutex_unlock(cap_mutex_t *mutex)
{
	return __cap_mutex_unlock(mutex);
}

/**
 * Generic cache wrappers.  Defined by platform-specific code and macros.
 */
#define cap_cache_create(__struct) __cap_cache_create(__struct)
#define cap_cache_create2(__struct,name) __cap_cache_create2(__struct,name)
static inline void cap_cache_destroy(cap_cache_t *cache)
{
	__cap_cache_destroy(cache);
}

static inline void *cap_cache_alloc(cap_cache_t *cache)
{
	return __cap_cache_alloc(cache);
}

static inline void *cap_cache_zalloc(cap_cache_t *cache)
{
	return __cap_cache_zalloc(cache);
}

static inline void cap_cache_free(cap_cache_t *cache, void *obj)
{
	__cap_cache_free(cache, obj);
}

/**
 * Spinlock wrappers.
 */
static inline void cap_set_bit(int nr, volatile unsigned long *addr)
{
	__cap_set_bit(nr, addr);
}

static inline void cap_clear_bit(int nr, volatile unsigned long *addr)
{
	__cap_clear_bit(nr, addr);
}

/**
 * Allocates a chunk of memory of 'nmemb * size' bytes. Returns NULL if the
 * allocation fails.
 */
static inline void *cap_zalloc(size_t nmemb, size_t size)
{
	return __cap_zalloc(nmemb, size);
}

static inline void cap_free(void *ptr)
{
	__cap_free(ptr);
}

#endif /* __LIBCAP_INTERNAL_H__ */
