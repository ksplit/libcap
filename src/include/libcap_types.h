/* 
 * types.h
 *
 * Author: Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 */
#ifndef __LIBCAP_TYPES_H__
#define __LIBCAP_TYPES_H__

#include <libcap_config.h>
#include <libcap_platform_types.h>

/* HELPERS -------------------------------------------------- */

/* Stolen from the Linux kernel */
#define CAP_DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define CAP_BITS_TO_LONGS(nr) CAP_DIV_ROUND_UP(nr, 8 * sizeof(long))

/* CONVENIENCE CALCULATIONS ---------------------------------------- */

/* 
 * To avoid serious CPP hacking, this is hard-coded for cspace depths. This
 * is still pretty fugly anyway.
 *
 * lvl must be a compile-time constant.
 *
 * IMPORTANT: lvl should be zero-indexed (the first level is lvl = 0, ...).
 * If you use a bad value, the error may not show up till link time.
 */
#if (CAP_CSPACE_DEPTH == 4)
#define CAP_EXP_0(a) (a)
#define CAP_EXP_1(a) ((a) * CAP_EXP_0(a))
#define CAP_EXP_2(a) ((a) * CAP_EXP_1(a))
#define CAP_EXP_3(a) ((a) * CAP_EXP_2(a))
#define CAP_CSPACE_SLOTS_IN_LEVEL(lvl) \
	CAP_EXP_ ## lvl(CAP_CSPACE_CNODE_TABLE_SIZE/2)
#else
#error "cspace depth not 4, you need to update this"
#endif

/* CPTRs -------------------------------------------------- */

/**
 * cptr_t -- Index into cspace radix tree (like a file descriptor)
 *
 * We wrap it inside a struct def so that the compiler will do strong
 * type checking.
 */
typedef struct {
	unsigned long cptr;
} cptr_t;

/**
 * Reserved cnodes:
 *
 * cptr = 0 is always null
 */
#define CAP_CPTR_NULL ((cptr_t){0})


/* CPTR CACHEs -------------------------------------------------- */

/* 
 * NOTE: This is part of the public interface so that it can be
 * allocated statically (e.g., as a global). This is needed for
 * LCDs because the cptr cache needs to be available before the
 * memory allocators are up and running.
 */

#if (CAP_CSPACE_DEPTH == 4)

struct cptr_cache {
	/* lock */
	cap_mutex_t lock;
	/* level 0 bitmap */
	unsigned long bmap0[CAP_BITS_TO_LONGS(CAP_CSPACE_SLOTS_IN_LEVEL(0))];
	/* level 1 bitmap */
	unsigned long bmap1[CAP_BITS_TO_LONGS(CAP_CSPACE_SLOTS_IN_LEVEL(1))];
	/* level 2 bitmap */
	unsigned long bmap2[CAP_BITS_TO_LONGS(CAP_CSPACE_SLOTS_IN_LEVEL(2))];
	/* level 3 bitmap */
	unsigned long bmap3[CAP_BITS_TO_LONGS(CAP_CSPACE_SLOTS_IN_LEVEL(3))];
};

#else
#error "You need to adjust the cptr cache def."
#endif

/* CSPACES -------------------------------------------------- */

/* For now, this def is not public, and hopefully never will be. */
struct cspace;

/* CNODES -------------------------------------------------- */

/* For now, this def is not public, and hopefully never will be. */
struct cnode;

/* CAP TYPE OPS ---------------------------------------- */

struct cap_type_ops {
	char *name;
	int (*delete)(struct cspace *cspace, struct cnode *cnode, void *object);
	int (*revoke)(struct cspace *cspace, struct cnode *cnode, void *object);
};

/* MISC -------------------------------------------------- */

/**
 * Maximum number of types allowed per type system
 */
#ifndef CAP_TYPE_MAX
#define CAP_TYPE_MAX 256
#endif

#endif /* __LIBCAP_TYPES_H__ */
