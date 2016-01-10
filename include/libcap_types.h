/* 
 * types.h
 *
 * Author: Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 */
#ifndef __LIBCAP_TYPES_H__
#define __LIBCAP_TYPES_H__

#include <config.h>

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
#define CAP_CSPACE_CNODE_TABLE_BITS 8
#define CAP_CSPACE_CNODE_TABLE_SIZE (1 << CAP_CSPACE_CNODE_TABLE_BITS)

#if (CAP_CSPACE_CNODE_TABLE_SIZE < 2)
#error "cnode table size must be at least 2"
#endif

/*
 * All of the data - the level, fanout sections, and slot - must fit
 * inside an unsigned long. The current configuration was chosen so
 * that this works on 32- and 64-bit. The cspace size is fairly
 * significant - over 200 million slot capacity.
 */
#if ((CAP_CSPACE_DEPTH * (CAP_CSPACE_CNODE_TABLE_BITS - 1) +	\
		CAP_CSPACE_DEPTH_BITS) > SIZEOF_UNSIGNED_LONG)
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
static inline int cap_cspace_slots_in_level(int lvl)
{
	int out = CAP_CSPACE_CNODE_TABLE_SIZE/2;
	if (lvl < 0 || lvl >= CAP_CSPACE_DEPTH)
		BUG();
	for ( ; lvl > 0; lvl-- )
		out *= CAP_CSPACE_CNODE_TABLE_SIZE/2;
	return out;
}

/* CPTRs -------------------------------------------------- */

typedef struct {
	unsigned long cptr;
} cptr_t;

static inline cptr_t __cptr(unsigned long cptr)
{
	return (cptr_t) {cptr};
}

static inline unsigned long cptr_val(cptr_t c)
{
	return c.cptr;
}

static inline unsigned long cap_cptr_slot(cptr_t c)
{
	/*
	 * Mask off low bits
	 */
	return cptr_val(c) & ((1 << (CAP_CSPACE_CNODE_TABLE_BITS - 1)) - 1);
}

/* 
 * Gives fanout index for going *from* lvl to lvl + 1, where 
 * 0 <= lvl < CAP_CSPACE_DEPTH.
 */
static inline unsigned long cap_cptr_fanout(cptr_t c, int lvl)
{
	unsigned long i;

	if (unlikely(lvl >= 3))
		BUG();

	i = cptr_val(c);
	/*
	 * Shift and mask off bits at correct section
	 */
	i >>= ((lvl + 1) * (CAP_CSPACE_CNODE_TABLE_BITS - 1));
	i &= ((1 << (CAP_CSPACE_CNODE_TABLE_BITS - 1)) - 1);

	return i;
}

/*
 * Gives depth/level of cptr, zero indexed (0 means the root cnode table)
 */
static inline unsigned long cap_cptr_level(cptr_t c)
{
	unsigned long i;

	i = cptr_val(c);
	/*
	 * Shift and mask
	 */
	i >>= (CAP_CSPACE_DEPTH * (CAP_CSPACE_CNODE_TABLE_BITS - 1));
	i &= ((1 << CAP_CSPACE_DEPTH_BITS) - 1);

	return i;
}

/*
 * Reserved cnodes:
 *
 * cptr = 0 is always null
 */
#define CAP_CPTR_NULL __cptr(0)

static inline int cptr_is_null(cptr_t c)
{
	return cptr_val(c) == cptr_val(CAP_CPTR_NULL);
}

/* CPTR CACHE -------------------------------------------------- */

#if (CAP_CSPACE_DEPTH == 4)

struct cptr_cache {
	/* level 0 bitmap */
	unsigned long bmap0[CAP_BITS_TO_LONGS(CAP_CSPACE_SLOTS_IN_LEVEL(0))];
	/* level 1 bitmap */
	unsigned long bmap1[CAP_BITS_TO_LONGS(CAP_CSPACE_SLOTS_IN_LEVEL(1))];
	/* level 2 bitmap */
	unsigned long bmap2[CAP_BITS_TO_LONGS(CAP_CSPACE_SLOTS_IN_LEVEL(2))];
	/* level 3 bitmap */
	unsigned long bmap3[CAP_BITS_TO_LONGS(CAP_CSPACE_SLOTS_IN_LEVEL(3))];
};

static inline unsigned long* 
cap_cptr_cache_bmap_for_level(struct cptr_cache *c, int lvl)
{
	switch (lvl) {
	case 0:
		return c->bmap0;
	case 1:
		return c->bmap1;
	case 2:
		return c->bmap2;
	case 3:
		return c->bmap3;
	default:
		BUG();
	}
}

#else
#error "You need to adjust the cptr cache def."
#endif

#endif				/* __LIBCAP_TYPES_H__ */
