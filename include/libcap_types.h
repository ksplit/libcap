/* 
 * types.h
 *
 * Author: Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 */
#ifndef __LIBCAP_TYPES_H__
#define __LIBCAP_TYPES_H__

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

#define CAP_CPTR_DEPTH_BITS  3	/* max depth of 3, zero indexed         */
#define CAP_CPTR_FANOUT_BITS 3	/* each level fans out by a factor of 4 */
#define CAP_CPTR_SLOT_BITS   3	/* each node contains 4 cap slots       */
#define CAP_CNODE_TABLE_NUM_SLOTS ((1 << CAP_CPTR_SLOT_BITS) + \
					(1 << CAP_CPTR_FANOUT_BITS))
#define CAP_CPTR_LEVEL_SHIFT (((1 << CAP_CPTR_DEPTH_BITS) - 1) * \
				CAP_CPTR_FANOUT_BITS + CAP_CPTR_SLOT_BITS)

static inline unsigned long cap_cptr_slot(cptr_t c)
{
	/*
	 * Mask off low bits
	 */
	return cptr_val(c) & ((1 << CAP_CPTR_SLOT_BITS) - 1);
}

/* 
 * Gives fanout index for going *from* lvl to lvl + 1, where 
 * 0 <= lvl < 2^CAP_CPTR_DEPTH_BITS - 1 (i.e., we can't go anywhere
 * if lvl = 2^CAP_CPTR_DEPTH_BITS - 1, because we are at the deepest
 * level).
 */
static inline unsigned long cap_cptr_fanout(cptr_t c, int lvl)
{
	unsigned long i;

	i = cptr_val(c);
	/*
	 * Shift and mask off bits at correct section
	 */
	i >>= (lvl * CAP_CPTR_FANOUT_BITS + CAP_CPTR_SLOT_BITS);
	i &= ((1 << CAP_CPTR_FANOUT_BITS) - 1);

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
	i >>= CAP_CPTR_LEVEL_SHIFT;
	i &= ((1 << CAP_CPTR_DEPTH_BITS) - 1);

	return i;
}

/* CPTR CACHE -------------------------------------------------- */

struct cptr_cache {
	unsigned long *bmaps[1 << CAP_CPTR_DEPTH_BITS];
};

#endif				/* __LIBCAP_TYPES_H__ */
