#ifndef __LIBCAP_USER_H__
#define __LIBCAP_USER_H__

#include <stdio.h>
#include <pthread.h>

CAP_BUILD_CORE_TYPES_NOBUILTIN();

#define __cap_err(format,...) \
    fprintf(stderr,"CERR: %s:%d: "format,__FUNCTION__,__LINE__,## __VA_ARGS__)
#define __cap_warn(format,...) \
    fprintf(stderr,"CWARN: %s:%d: "format,__FUNCTION__,__LINE__,## __VA_ARGS__)
#define __cap_msg(format,...) \
    fprintf(stderr,"CINFO: %s:%d: "format,__FUNCTION__,__LINE__,## __VA_ARGS__)
#define __cap_debug(format,...) \
    fprintf(stderr,"CDEBUG: %s:%d: "format,__FUNCTION__,__LINE__,## __VA_ARGS__)

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

#endif /* __LIBCAP_USER_H__ */
