/**
 * cptr_cache.c
 *
 * Authors:
 *   Charlie Jacobsen  <charlesj@cs.utah.edu>
 *   Pankaj Kumar <pankajk@cs.utah.edu>
 */

#ifdef LCD_DOMAINS
#include <lcd_config/pre_hook.h>
#endif

#include <libcap.h>
#include <libcap_internal.h>

#ifdef LCD_DOMAINS
#include <lcd_config/post_hook.h>
#endif

int 
LIBCAP_FUNC_ATTR
cptr_cache_alloc(struct cptr_cache **out)
{
	struct cptr_cache *cache;
	/*
	 * Allocate the container
	 */
	cache = cap_zalloc(1, sizeof(*cache));
	if (!cache)
		return -ENOMEM;
	*out = cache;
	return 0;
}

void 
LIBCAP_FUNC_ATTR
cptr_cache_free(struct cptr_cache *cache)
{
	/*
	 * Free container
	 */
	cap_free(cache);
}

int 
LIBCAP_FUNC_ATTR
cptr_cache_init(struct cptr_cache *cache)
{
	int i;
	unsigned long *bmap;
	/*
	 * Init lock
	 */
	cap_mutex_init(&cache->lock);
	/*
	 * Zero out the bitmaps. (The caller may not have
	 * necessarily used zalloc.)
	 */
	for (i = 0; i < CAP_CSPACE_DEPTH; i++) {
		bmap = cap_cptr_cache_bmap_for_level(cache, i);
		memset(bmap, 
			0, 
			CAP_BITS_TO_LONGS(cap_cspace_slots_in_level(i)));
	}
	/*
	 * Mark reserved cptr's as allocated
	 */
	cap_set_bit(0, cap_cptr_cache_bmap_for_level(cache, 0));

	return 0;
}

void 
LIBCAP_FUNC_ATTR
cptr_cache_destroy(struct cptr_cache *cache)
{
	/* No-op for now */
}

static int __cap_alloc_cptr_from_bmap(unsigned long *bmap, int size,
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

int 
LIBCAP_FUNC_ATTR
cptr_alloc(struct cptr_cache *cptr_cache, cptr_t *free_cptr)
{
	int ret;
	int depth;
	int done;
	unsigned long *bmap;
	unsigned long idx;
	int size;
	cptr_t result;
	/*
	 * Lock cache ********************
	 */
	cap_mutex_lock(&cptr_cache->lock);
	/*
	 * Search
	 */
	depth = 0;
	do {
		bmap = cap_cptr_cache_bmap_for_level(cptr_cache, depth);
		size = cap_cspace_slots_in_level(depth);
		done = __cap_alloc_cptr_from_bmap(bmap, size, &idx);
		depth++;
	} while (!done && depth < CAP_CSPACE_DEPTH);

	if (!done) {
		/*
		 * Didn't find one
		 */
		CAP_ERR("out of cptrs");
		ret = -ENOMEM;
		goto unlock;
	}
	/*
	 * Found one; dec depth back to what it was, and encode
	 * depth in cptr
	 */
	depth--;
	result = __cptr(idx);
	cap_cptr_set_level(&result, depth);
	*free_cptr = result;

	ret = 0;
	goto unlock;

unlock:
	/*
	 * Unlock cache ********************
	 */
	cap_mutex_unlock(&cptr_cache->lock);
	return ret;
}

void 
LIBCAP_FUNC_ATTR
cptr_free(struct cptr_cache *cptr_cache, cptr_t c)
{
	unsigned long *bmap;
	unsigned long bmap_idx;
	unsigned long level;
	unsigned long mask;
	/*
	 * Lock cache ********************
	 */
	cap_mutex_lock(&cptr_cache->lock);
	/*
	 * Get the correct level bitmap
	 */
	level = cap_cptr_level(c);
	bmap = cap_cptr_cache_bmap_for_level(cptr_cache, level);
	/*
	 * The bitmap index includes all fanout bits and the slot bits (this
	 * is what makes allocation fast and easy).
	 *
	 * It's also a good idea to mask off in case some stray erroneous bits
	 * ended up in the cptr.
	 */
	mask = (1 << ((level + 1) * (CAP_CSPACE_CNODE_TABLE_BITS - 1))) - 1;
	bmap_idx = cptr_val(c) & mask;
	/*
	 * Clear the bit in the bitmap
	 */
	cap_clear_bit(bmap_idx, bmap);
	/*
	 * Unlock cache ********************
	 */
	cap_mutex_unlock(&cptr_cache->lock);

	return;
}

/* EXPORTS -------------------------------------------------- */

/* These are required for kernel land, so that if we install libcap
 * as a kernel module, other kernel code can link with it. */
EXPORT_SYMBOL(cap_cptr_cache_bmap_for_level);
EXPORT_SYMBOL(cptr_cache_alloc);
EXPORT_SYMBOL(cptr_cache_free);
EXPORT_SYMBOL(cptr_cache_init);
EXPORT_SYMBOL(cptr_cache_destroy);
EXPORT_SYMBOL(cptr_alloc);
EXPORT_SYMBOL(cptr_free);
