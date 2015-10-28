/**
 * cptr_cache.c
 *
 * Authors:
 *   Charlie Jacobsen  <charlesj@cs.utah.edu>
 *   Pankaj Kumar <pankajk@cs.utah.edu>
 */

#include "../include/internal.h"
#include "../include/types.h"
#include "../include/list.h"
#define ENOMEM 1

#ifndef __WORDSIZE
#define __WORDSIZE (sizeof(long) * 8)
#endif

#define BITS_PER_LONG __WORDSIZE

#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE           8
/*#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITS_TO_U64(nr)         DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(u64))
#define BITS_TO_U32(nr)         DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(u32))
#define BITS_TO_BYTES(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE)
*/
#ifndef min
#define min(x, y) ({                            \
        typeof(x) _min1 = (x);                  \
        typeof(y) _min2 = (y);                  \
        (void) (&_min1 == &_min2);              \
        _min1 < _min2 ? _min1 : _min2; })
#endif

static inline void set_bit(int nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
        unsigned long flags;

//        _atomic_spin_lock_irqsave(p, flags); Need to find counter parts!!
        *p  |= mask;
//        _atomic_spin_unlock_irqrestore(p, flags);
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
        unsigned long mask = BIT_MASK(nr);
        unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
        unsigned long flags;

//        _atomic_spin_lock_irqsave(p, flags);
        *p &= ~mask;
//        _atomic_spin_unlock_irqrestore(p, flags);
}

static inline unsigned long ffz(unsigned long word)
{
        asm("rep; bsf %1,%0"
                : "=r" (word)
                : "r" (~word));
        return word;
}

unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
        unsigned long idx;

        for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
                if (addr[idx] != ~0UL)
                        return min(idx * BITS_PER_LONG + ffz(addr[idx]), size);
        }

        return size;
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
#ifdef KERNEL
	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
#else
	//cache = (struct cptr_cache *) malloc(1 * sizeof(struct cptr_cache));
	cache = (struct cptr_cache *) malloc(1 * sizeof(*cache));
#endif
	if (!cache) {
		//ret = -ENOMEM;
		ret = -1;
		goto fail1;
	}
	/*
	 * Allocate the bitmaps
	 */
	for (i = 0; i < (1 << LCD_CPTR_DEPTH_BITS); i++) {
		/*
		 * For level i, we use the slot bits plus i * fanout bits
		 *
		 * So e.g. for level 0, we use only slot bits, so there
		 * are only 2^(num slot bits) cap slots at level 0.
		 */
		nbits = 1 << (LCD_CPTR_SLOT_BITS + i * LCD_CPTR_FANOUT_BITS);
		/*
		 * Alloc bitmap
		 */
#ifdef KERNEL
		cache->bmaps[i] = kzalloc(sizeof(unsigned long) *
					BITS_TO_LONGS(nbits),
					GFP_KERNEL);
#else
		cache->bmaps[i] = malloc(sizeof(unsigned long) *
					BITS_TO_LONGS(nbits));
#endif
		if (!cache->bmaps[i]) {
			ret = -ENOMEM;
			goto fail2; /* i = level we failed at */
		}
	}
	/*
	 * Mark reserved cptr's as allocated
	 */
	set_bit(0, cache->bmaps[0]);

	*out = cache;

	return 0;

fail2:
	for (j = 0; j < i; j++)
#ifdef KERNEL
		kfree(cache->bmaps[j]);
	kfree(cache);
#else
		free(cache->bmaps[j]);
	free(cache);
#endif
fail1:
	return ret;
}

static void cptr_cache_destroy(struct cptr_cache *cache)
{
	int i;
	/*
	 * Free bitmaps
	 */
	for (i = 0; i < (1 << LCD_CPTR_DEPTH_BITS); i++)
#ifdef KERNEL
		kfree(cache->bmaps[i]);
	/*
	 * Free container
	 */
	kfree(cache);
#else
		free(cache->bmaps[i]);
	free(cache);
#endif
}

int __lcd_alloc_cptr_from_bmap(unsigned long *bmap, int size,
				unsigned long *out)
{
	unsigned long idx;
	/*
	 * Find next zero bit
	 */
	idx = find_first_zero_bit(bmap, size);
	if (idx >= size)
		return 0; /* signal we are full */
	/*
	 * Set bit to mark cptr as in use
	 */
	set_bit(idx, bmap);

	*out = idx;

	return 1; /* signal we are done */
}

int __klcd_alloc_cptr(struct cptr_cache *cptr_cache, cptr_t *free_cptr)
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
		size = 1 << (LCD_CPTR_SLOT_BITS + 
			depth * LCD_CPTR_FANOUT_BITS);
		done = __lcd_alloc_cptr_from_bmap(bmap, size, &idx);
		depth++;
	} while (!done && depth < (1 << LCD_CPTR_DEPTH_BITS));

	if (!done) {
		/*
		 * Didn't find one
		 */
		LCD_ERR("out of cptrs");
		ret = -ENOMEM;
		goto fail2;
	}
	/*
	 * Found one; dec depth back to what it was, and encode
	 * depth in cptr
	 */
	depth--;
	idx |= (depth << LCD_CPTR_LEVEL_SHIFT);
	*free_cptr = __cptr(idx);

	return 0; 

fail2:
	return ret;
}

void __klcd_free_cptr(struct cptr_cache *cptr_cache, cptr_t c)
{
	unsigned long *bmap;
	unsigned long bmap_idx;
	unsigned long level;

	/*
	 * Get the correct level bitmap
	 */
	level = lcd_cptr_level(c);
	bmap = cptr_cache->bmaps[level];
	/*
	 * The bitmap index includes all fanout bits and the slot bits
	 */
	bmap_idx = ((1 << (LCD_CPTR_FANOUT_BITS * level + LCD_CPTR_SLOT_BITS))
		- 1) & cptr_val(c);
	/*
	 * Clear the bit in the bitmap
	 */
	clear_bit(bmap_idx, bmap);

	return; 
}

int klcd_alloc_cptr(cptr_t *free_slot)
{
	struct cptr_cache *cache;
	//return __lcd_alloc_cptr(current->cptr_cache, free_slot);
	//return __lcd_alloc_cptr(cache, free_slot);
	return 0;
}

void klcd_free_cptr(cptr_t c)
{
	struct cptr_cache *cache;
	//__lcd_free_cptr(current->cptr_cache, c);
	//__lcd_free_cptr(cache, c);
}

int klcd_init_cptr(struct cptr_cache **c_out)
{
	return cptr_cache_init(c_out);
}

void klcd_destroy_cptr(struct cptr_cache *c)
{
	cptr_cache_destroy(c);
}
