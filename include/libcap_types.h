/* 
 * types.h
 *
 * Author: Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 */
#ifndef __LIBCAP_TYPES_H__
#define __LIBCAP_TYPES_H__

#include "libcap_config.h"

/* HELPERS -------------------------------------------------- */

/* Stolen from the Linux kernel */
#define CAP_DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define CAP_BITS_TO_LONGS(nr) CAP_DIV_ROUND_UP(nr, 8 * sizeof(long))

/* CSPACE CONFIGURATION ---------------------------------------- */

/* 
 * Controls how many levels can be in the cspace radix tree.
 *
 * The depth must be at least 1 and a power of 2, since there is always at 
 * least one root level.
 */
#define CAP_CSPACE_DEPTH_BITS 2
#define CAP_CSPACE_DEPTH (1 << CAP_CSPACE_DEPTH_BITS)

#if (CAP_CSPACE_DEPTH < 1)
#error "cspace depth must be at least 1"
#endif

/*
 * Controls the size of each node in the cspace radix tree, and the
 * degree of fanout. Each node in the radix tree contains
 * CAP_CSPACE_CNODE_TABLE_SIZE slots; the first half store capabilities,
 * and the second half store pointers to further nodes in the tree.
 *
 * The table size must be a power of 2 and at least 2, (1) because of how the 
 * cptr allocation algorithm works, and (2) because a cnode table needs at 
 * least one capability slot and one pointer slot.
 */
#define CAP_CSPACE_CNODE_TABLE_BITS 6
#define CAP_CSPACE_CNODE_TABLE_SIZE (1 << CAP_CSPACE_CNODE_TABLE_BITS)

#if (CAP_CSPACE_CNODE_TABLE_SIZE < 2)
#error "cnode table size must be at least 2"
#endif

/*
 * All of the data - the level, fanout sections, and slot - must fit
 * inside an unsigned long. The current configuration was chosen so
 * that this works on 32- and 64-bit. The cspace size is fairly
 * significant - over 1 million slot capacity. You don't want it to
 * be too big or else the (inefficient) cptr cache with bitmaps will
 * be enormous.
 */
#if ((CAP_CSPACE_DEPTH * (CAP_CSPACE_CNODE_TABLE_BITS - 1) +	\
		CAP_CSPACE_DEPTH_BITS) > (SIZEOF_UNSIGNED_LONG * 8))
#error "Adjust cspace sizing, otherwise cptrs won't work."
#endif

/* CONVENIENCE CALCULATIONS ---------------------------------------- */

/* 
 * To avoid serious CPP hacking, this is hard-coded for cspace depths. This
 * is still pretty fugly anyway.
 *
 * lvl must be a compile-time constant. Use the static inline function
 * below instead otherwise.
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

/*
 * Reserved cnodes:
 *
 * cptr = 0 is always null
 */
#define CAP_CPTR_NULL ((cptr_t){0})



#endif				/* __LIBCAP_TYPES_H__ */
