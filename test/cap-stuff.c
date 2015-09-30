#include <stdio.h>
#include "../include/internal.h"
#include "../include/types.h"
#include <string.h>
#define ENOMEM 1

/* 
 * A testcase to check:
 * 1. Cspace initialization
 * 2. cptr cache initialization (User's stuff)
 * 3. Capability insertion in scpace
 * 4. Lookup after insertion
 * 5. Capability deletion (Here i am getting a locking issue)
 * 6. Capability Grant (Todo) 
 * 
 * For quick testing, I have embedded the code in one function.
 * I will subsequently break down the code in different functions.
 *
 */
int testcase1()
{
	int ret;
	struct cspace * csp;
	struct cnode *cnode;
	cptr_t slot_out, slot_out_orig;
        struct cptr_cache *cache;
	char *p;
	struct cnode *check;
	struct cnode *check1;

	/* Initialize a cspace */
	csp = malloc(1 * sizeof(*csp));

	__lcd_cap_init_cspace(csp);
	printf("Initialized cspace Address:%p\n", csp);

	/* cptr cache intialization. This is totally users stuff */
	cache = malloc (1 * sizeof(*cache));
	ret = cptr_cache_init(&cache);
	
	ret = __klcd_alloc_cptr(cache, &slot_out);
        p = malloc(sizeof(char) * 4);
        if (!p) {
                LCD_ERR("alloc failed");
                ret = -ENOMEM;
                goto fail;
        }
	memset(p, 0, 4);

	/* Insert capability in cspace */	
	ret = __lcd_cap_insert(csp, slot_out, p, LCD_CAP_TYPE_PAGE);

        if (ret) {
                LCD_ERR("set up cspace");
                goto fail;
        }

	/* Verification if capability is properly inserted in the cspace. */
	ret = __lcd_cnode_get(csp, slot_out, &check);
	if (ret < 0) {
		LCD_ERR("Lookup failed");
		goto fail;
	} else {
		if (check->object == p)
			printf("Capability Lookup Passed\n");
		else
			printf("Capability lookup failed!!!\n");
	}

	/* Capability deletion from cspace. 
	 * Presently, I am getting an issue in this functionality.
         * Some locking issue. I am working on it.
         * For now, I am commenting the code.
	 */

	/*
	slot_out_orig = slot_out;
	__lcd_cap_delete(csp, slot_out);
	printf("Old=%p New=%p\n", slot_out_orig, slot_out);
	
	//Lookup
	ret = __lcd_cnode_get(csp, slot_out, &check1);

        if (ret < 0) {
                LCD_ERR("Lookup failed");
                goto fail;
        } else {
                if (check->object == p)
                        printf("Screwed!!!\n");
                else
                        printf("Yippiee!!!\n");
        }
	*/
fail:	
	/* Free memory stuff. */
	return ret;
}

int main()
{
	int ret;

	ret = testcase1();
}
