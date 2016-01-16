#ifndef __LIBCAP_COMPAT_INTERNAL_OSX_USER_H__
#define __LIBCAP_COMPAT_INTERNAL_OSX_USER_H__

#include <Availability.h>

#ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
	#if __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_4
		#error "OSSpinLock only supported from on OSX 10.4+"
	#endif
#else
	#error "__MAC_OS_X_VERSION_MIN_REQUIRED macro not supported on this platform"
#endif

#include <assert.h>
#include <libkern/OSAtomic.h>

typedef OSSpinLock pthread_spinlock_t;

static int pthread_spin_init(pthread_spinlock_t *lock, int pshared) {
	assert(pshared == PTHREAD_PROCESS_PRIVATE &&
		   "PTHREAD_PROCESS_SHARED not supported on OSX");
	*lock = OS_SPINLOCK_INIT;
	return 0;
}

static int pthread_spin_destroy(pthread_spinlock_t *lock) { return 0; }

static int pthread_spin_lock(pthread_spinlock_t *lock) {
	OSSpinLockLock(lock);
	return 0;
}

/* OSSpinLockTry returns false when it fails to acquire the lock, seems
 * to be equivalent to EBUSY under the standard API */
static int pthread_spin_trylock(pthread_spinlock_t *lock) { 
	if (OSSpinLockTry(lock) == true) {
		return 0;
	} else {
		return EBUSY;
	}
}
static int pthread_spin_unlock(pthread_spinlock_t *lock) { 
	OSSpinLockUnlock(lock);
	return 0;
}

#endif
