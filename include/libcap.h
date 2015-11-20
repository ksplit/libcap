/* 
 * libcap primary header file and interface.
 *
 * Author: Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 * This is the non-isolated code interface to the microkernel. The
 * implementation is in virt/lcd-domains/kliblcd.c.
 *
 * An LCD that runs in non-isolated code is called a klcd.
 */
#ifndef __LIBCAP_H__
#define __LIBCAP_H__

#include "libcap_types.h"

struct cnode;
struct cspace;

struct cap_type_ops {
	char *name;
	int (*delete)(struct cspace *cspace, struct cnode *cnode, void *object);
	int (*revoke)(struct cspace *cspace, struct cnode *cnode, void *object);
};

/*
 * Add some macros to generate built-in capability object type.  Not
 * ideal to put this here, but don't want to expose internal headers,
 * and have to give per-platform a chance to change them.
 */
#define CAP_BUILD_CORE_TYPES(PT)				\
	typedef enum cap_type {					\
		CAP_TYPE_ERR = -1,				\
		CAP_TYPE_NONE = 0,				\
		CAP_TYPE_INVALID,				\
		CAP_TYPE_FREE,					\
		CAP_TYPE_CNODE,					\
		PT,						\
		CAP_TYPE_FIRST_NONBUILTIN			\
	} cap_type_t
#define CAP_BUILD_CORE_TYPES_NOBUILTIN()			\
	typedef enum cap_type {					\
		CAP_TYPE_NONE = 0,				\
		CAP_TYPE_INVALID,				\
		CAP_TYPE_FREE,					\
		CAP_TYPE_CNODE,					\
		CAP_TYPE_FIRST_NONBUILTIN			\
	} cap_type_t

#ifdef __KERNEL__
#include "libcap_kernel.h"
#else
#include "libcap_user.h"
#endif

#ifndef CAP_TYPE_MAX
#define CAP_TYPE_MAX 256
#endif

/**
 * Initalize the cptr cache subsystem
 */
void cptr_init(void);
/**
 * Allocate and initialize a new cptr_cache.
 */
int cptr_cache_init(struct cptr_cache **c_out);
/**
 * Free and delete a cptr_cache
 */
void cptr_cache_destroy(struct cptr_cache *c);
/**
 * Allocate a new cptr in the given cptr_cache. The cptr is stored in the memory
 * pointed to by 'free_cptr'.
 */
int cptr_alloc(struct cptr_cache *cptr_cache, cptr_t *free_cptr);
/**
 * Remove the value pointed to by the
 */
void cptr_free(struct cptr_cache *cptr_cache, cptr_t c);

/**
 * Initializes caches, etc. in capability subsystem. Called when microkernel
 * intializes.
 */
int cap_init(void);
/**
 * Tears down caches, etc. in capability subsystem. Called when microkernel
 * is exiting.
 */
void cap_fini(void);
/**
 * Register a new capability object type.  If you pass type == 0, the
 * system will select the next available identifier and return it.  You
 * should use the returned value as your object identifier.  If you
 * attempt to use a type that is already in use, this returns
 * -EADDRINUSE.  If there are no types remaining or you exceed
 * CAP_TYPE_MAX, this returns -ENOMEM .
 */
cap_type_t cap_register_type(cap_type_t type, const struct cap_type_ops *ops);
/**
 * Revoke all derived capabilities.
 *
 * Does not delete the caller's capability.
 *
 * This may change the state of the lcd's whose capabilities are revoked (see
 * comment lcd_cap_delete).
 */
int cap_revoke(struct cspace *cspace, cptr_t c);
/**
 * Delete the capability in slot from this cspace.
 *
 * This may change the state of the caller. (For example, if the caller is
 * a regular lcd, and if the capability is to a page, the page will be unmapped
 * from the caller's address space.)
 *
 * If this is the last capability to the object, the object will be destroyed,
 * unless it is a kernel page. See klcd_add_page and klcd_rm_page.
 */
void cap_delete(struct cspace *cspace, cptr_t c);

/**
 * Allocates a new cspace. If no memory could be allocated, returns NULL.
 */
struct cspace * cap_alloc_cspace(void);

/**
 * Frees a cspace allocated with `cap_alloc_cspace`.
 */
void cap_free_cspace(struct cspace *cspace);

/**
 * Sets up cspace - initializes lock, root cnode table, etc.
 */
int cap_init_cspace(struct cspace *cspace);
/**
 * Set the "owner" field of the given cspace
 */
void cap_cspace_setowner(struct cspace *cspace, void * owner);
/**
 * Get the "owner" field of the given cspace
 */
void* cap_cspace_getowner(struct cspace *cspace);
/**
 * Inserts object data into cspace at cnode pointed at by c.
 */
int cap_insert(struct cspace *cspace, cptr_t c, void *object, cap_type_t type);
/**
 * Deletes object data from cspace at cnode pointed at by c.
 *
 * Updates the state of the microkernel to reflect rights change (e.g., if
 * a cnode for a page is deleted, and the page is mapped, the page will be
 * unmapped).
 *
 * If this is the last cnode that refers to the object, the object is
 * destroyed.
 */
void cap_delete(struct cspace *cspace, cptr_t c);
/**
 * Copies cnode data in src cnode at c_src to dest cnode at c_dst. The dest
 * cnode will be a child of the src cnode in the cdt containing src cnode.
 */
int cap_grant(struct cspace *cspacesrc, cptr_t c_src,
	      struct cspace *cspacedst, cptr_t c_dst);
/**
 * Equivalent to calling lcd_cap_delete on all of the cnode's children. 
 *
 * ** Does not delete the cnode itself. **
 */
int cap_revoke(struct cspace *cspace, cptr_t c);
/**
 * Equivalent to calling lcd_cap_delete on all cnodes in cspace. Frees up
 * all cnode tables, etc.
 */
void cap_destroy_cspace(struct cspace *cspace);
/**
 * Looks up cnode at cap in cspace.
 *
 * ** Frees the cnode lock itself without relying on user.
 *
 * ** Interrupts and preemption *are not* disabled. **
 *    (so we can easily get out of deadlocks while debugging)
 */
int cap_cnode_verify(struct cspace *cspace, cptr_t cap);
/**
 * Return the cptr that points to this cnode.
 */
cptr_t cap_cnode_cptr(struct cnode *cnode);

/**
 * Return the cnode that this cptr points to in the given cspace. Acquires
 * a lock to the cnode. Returns zero on success. Make sure to call
 * cap_cnode_put after every cap_cnode_get.
 */
int cap_cnode_get(struct cspace *cspace, cptr_t cptr, struct cnode **cnode);

/**
 * Unlock the cnode. Call this on every cnode you've called
 * cap_cnode_get on.
 */
void cap_cnode_put(struct cnode *cnode);

/**
 * Get the object stored at this cnode.
 */
void* cap_cnode_object(struct cnode *cnode);

/**
 * For now, put debug macros in the user-accessible part; convenient.
 */
extern int cap_debug_level;

#define CAP_ERR __cap_err
#define CAP_WARN __cap_warn
#define CAP_MSG __cap_msg

#define CAP_DEBUG_ERR  1
#define CAP_DEBUG_WARN 2
#define CAP_DEBUG_MSG  3

#define CAP_DEBUG(lvl, msg, ...) {					\
	if (lvl <= cap_debug_level)					\
	    __cap_debug(msg,## __VA_ARGS__);				\
	}

#endif /* __LIBCAP_H__ */
