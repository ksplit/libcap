/**
 * cptr_cache.c
 *
 * Authors:
 *   Charlie Jacobsen  <charlesj@cs.utah.edu>
 *   Pankaj Kumar <pankajk@cs.utah.edu>
 */

#include "libcap.h"
#include "libcap_types.h"
#include "libcap_internal.h"

void cptr_init(void)
{
	__cptr_init();
}

void cptr_fini(void)
{
	__cptr_fini();
}

int cptr_cache_init(struct cptr_cache **out)
{
	struct cptr_cache *cache;
	int ret;
	int i, j;
	int nbits;
	/*
	 * Allocate the container
	 */
	cache = cap_zalloc(1, sizeof(*cache));
	if (!cache) {
		ret = -ENOMEM;
		goto fail1;
	}
	/*
	 * Allocate the bitmaps
	 */
	for (i = 0; i < (1 << CAP_CPTR_DEPTH_BITS); i++) {
		/*
		 * For level i, we use the slot bits plus i * fanout bits
		 *
		 * So e.g. for level 0, we use only slot bits, so there
		 * are only 2^(num slot bits) cap slots at level 0.
		 */
		nbits = 1 << (CAP_CPTR_SLOT_BITS + i * CAP_CPTR_FANOUT_BITS);
		/*
		 * Alloc bitmap
		 */
		cache->bmaps[i] = cap_zalloc(BITS_TO_LONGS(nbits),
					     sizeof(unsigned long));
		if (!cache->bmaps[i]) {
			ret = -ENOMEM;
			goto fail2;	/* i = level we failed at */
		}
	}
	/*
	 * Mark reserved cptr's as allocated
	 */
	cap_set_bit(0, cache->bmaps[0]);

	*out = cache;

	return 0;

 fail2:
	for (j = 0; j < i; j++)
		cap_free(cache->bmaps[j]);
	cap_free(cache);
 fail1:
	return ret;
}

void cptr_cache_destroy(struct cptr_cache *cache)
{
	int i;
	/*
	 * Free bitmaps
	 */
	for (i = 0; i < (1 << CAP_CPTR_DEPTH_BITS); i++)
		cap_free(cache->bmaps[i]);
	/*
	 * Free container
	 */
	cap_free(cache);
}

int __cap_alloc_cptr_from_bmap(unsigned long *bmap, int size,
			       unsigned long *out)
{
	unsigned long idx;
	/*
	 * Find next zero bit
	 */
	idx = find_first_zero_bit(bmap, size);
	if (idx >= size)
		return 0;	/* signal we are full */
	/*
	 * Set bit to mark cptr as in use
	 */
	cap_set_bit(idx, bmap);

	*out = idx;

	return 1;		/* signal we are done */
}

int cptr_alloc(struct cptr_cache *cptr_cache, cptr_t *free_cptr)
{
	int ret;
	int depth;
	int done;
	unsigned long *bmap;
	unsigned long idx;
	int size;

	depth = 0;
	do {
		bmap = cptr_cache->bmaps[depth];
		size = 1 << (CAP_CPTR_SLOT_BITS + depth * CAP_CPTR_FANOUT_BITS);
		done = __cap_alloc_cptr_from_bmap(bmap, size, &idx);
		depth++;
	} while (!done && depth < (1 << CAP_CPTR_DEPTH_BITS));

	if (!done) {
		/*
		 * Didn't find one
		 */
		CAP_ERR("out of cptrs");
		ret = -ENOMEM;
		goto fail2;
	}
	/*
	 * Found one; dec depth back to what it was, and encode
	 * depth in cptr
	 */
	depth--;
	idx |= (depth << CAP_CPTR_LEVEL_SHIFT);
	*free_cptr = __cptr(idx);

	return 0;

 fail2:
	return ret;
}

void cptr_free(struct cptr_cache *cptr_cache, cptr_t c)
{
	unsigned long *bmap;
	unsigned long bmap_idx;
	unsigned long level;

	/*
	 * Get the correct level bitmap
	 */
	level = cap_cptr_level(c);
	bmap = cptr_cache->bmaps[level];
	/*
	 * The bitmap index includes all fanout bits and the slot bits
	 */
	bmap_idx = ((1 << (CAP_CPTR_FANOUT_BITS * level + CAP_CPTR_SLOT_BITS))
		    - 1) & cptr_val(c);
	/*
	 * Clear the bit in the bitmap
	 */
	cap_clear_bit(bmap_idx, bmap);

	return;
}
