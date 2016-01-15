/*
 * libcap_platform_types.h
 *
 * User-specific typedefs, etc.
 *
 * Copyright: University of Utah
 */
#ifndef __LIBCAP_PLATFORM_TYPES_H__
#define __LIBCAP_PLATFORM_TYPES_H__

#include <pthread.h>

/*
 * Locks
 *
 * It would be nice to hide this, but:
 *   1 - we want libcap users (like LCDs) to be able to statically
 *       allocate a cptr_cache
 *   2 - (1) implies the cptr_cache def must go in the public header
 *   3 - since the cptr_cache uses a lock, its def must also be public
 */
typedef pthread_mutex_t cap_mutex_t;

/* Capability type system */
typedef enum cap_type {
	CAP_TYPE_ERR = -1,
	CAP_TYPE_NONE = 0,
	CAP_TYPE_INVALID,
	CAP_TYPE_FREE,
	CAP_TYPE_CNODE,
	CAP_TYPE_FIRST_NONBUILTIN
} cap_type_t;

#endif /* __LIBCAP_PLATFORM_TYPES_H__ */
