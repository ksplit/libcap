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
 * 5. Capability deletion 
 * 6. Capability Grant 
 * 7. Make code modular (Todo)
 * 8. Test with multiple threads (In process) 
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
	printf("\nTestCase : Cspace Initialization.\n");
	ret = __lcd_cap_init_cspace(csp);
	if (ret < 0)
		printf("Cspace Initialization Failed!!\n");
	else
		printf("Cspace Initialization Passed Address:%p \n", csp);

	/* cptr cache intialization. This is totally users stuff */
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
	printf("\nTestCase : Add Capability to Cspace.\n");
	ret = __lcd_cap_insert(csp, slot_out, p, LCD_CAP_TYPE_PAGE);

        if (ret) {
                LCD_ERR("cap insertion failed\n");
                goto fail;
        }

	/* Verification if capability is properly inserted in the cspace. */
	ret = __lcd_cnode_get(csp, slot_out, &check);
	if (ret < 0) {
		LCD_ERR("Lookup failed");
		goto fail;
	} else {
		if (check->object == p)
			printf("Capability Addition & Lookup Passed\n");
		else
			printf("Capability Addition & Lookup Failed!!!\n");
	}
	/* Release cnode Lock */
	__lcd_cnode_put(check);

	/* Capability deletion from cspace. 
	 */
	printf("\nTestCase : Delete Capability from Cspace.\n");
	__lcd_cap_delete(csp, slot_out);
	
	/*Lookup after deleting capability. It should Fail!!
	 */
	ret = __lcd_cnode_get(csp, slot_out, &check1);
        if (ret < 0) {
                LCD_ERR("Lookup failed\n");
		printf("Capability Deletion Passed\n");
        } else {
                if (check1->object == p)
                        printf("Screwed!!!\n");
                else
                        printf("Yippiee!!!\n");
        }
	/* Release cnode Lock */
	__lcd_cnode_put(check1);

	/* Free the cspace 
	 * Here we will destory the cspace.
	 * We will confirm the deletion after making a
	 * __lcd_cap_insert call. If the call fails, that means
	 * cspace has been deleted successfully.
	 */
	printf("\nTestCase : Delete Cspace.\n");
	__lcd_cap_destroy_cspace(csp);

	/* To check id cspace has been successfully destroyed,
	 * try to insert capability in cspace. Following call should
         * return error.
	 */
        ret = __lcd_cap_insert(csp, slot_out, p, LCD_CAP_TYPE_PAGE);

        if (ret) {
		printf("Cspace Deletion Passed\n");
                goto fail;
        }
fail:	
	/* Free memory stuff. */
	return ret;
}

int testcase_grant()
{
	int ret;
	struct cspace *scsp, *dcsp;
	struct cnode *cnode;
	cptr_t sslot, dslot;
	struct cptr_cache *scache, *dcache;
	char *p;
	struct cnode *scnode;
	struct cnode *dcnode;

	/* Initialize Source cspace */
	scsp = malloc(1 * sizeof(*scsp));
	ret = __lcd_cap_init_cspace(scsp);
	//ret = cspace_init(scsp);
	if (ret < 0) {
		printf("Cspace Setup Failed\n");
		return ret;
	}
	printf("Source Cspace Initilaized: Address=%p\n", scsp);

	/* cptr cache intialization. This is totally users stuff */
	ret = cptr_cache_init(&scache);
	if (ret < 0) {
		printf("Cache Initilization failed\n");
		goto fail1;
	}

	ret = __klcd_alloc_cptr(scache, &sslot);
	if (ret < 0) {
		printf("cptr allocation Failed!!\n");
		goto fail1;
	}
	p = malloc(sizeof(char) * 4);
	/* Insert capability in cspace */
	ret = __lcd_cap_insert(scsp, sslot, p, LCD_CAP_TYPE_PAGE);
	if (ret) {
		LCD_ERR("cap insertion failed\n");
		goto fail1;
	}
	printf("Added capability [%p] to Source cspace\n", p);

	/* Setup destination cspace */
	dcsp = malloc(1 * sizeof(*dcsp));
        ret = __lcd_cap_init_cspace(dcsp);
	if (ret < 0) {
		printf("Cspace Setup Failed\n");
		return ret;
	}
	printf("Destination Cspace Initilaized: Address=%p\n", dcsp);

	ret = cptr_cache_init(&dcache);
	if (ret < 0) {
		printf("Cache Initilization failed\n");
		goto fail2;
	}

	ret = __klcd_alloc_cptr(dcache, &dslot);
	if (ret < 0) {
		printf("cptr allocation Failed!!\n");
		goto fail2;
	}
	
	ret = libcap_grant_capability((void *)scsp, (void *)dcsp, sslot, dslot);
	if (ret < 0) {
		printf("Granting capability failed\n");
		goto fail2;
	}

	ret = __lcd_cnode_get(dcsp, dslot, &dcnode);
	if (ret < 0) {
		LCD_ERR("Lookup failed\n");
		goto fail2;
	} else {
		if (dcnode->object == p) {
			printf("Capability granted successfully from Cspace[%p] at slot 0x%lx \
			to Cspace[%p] at slot 0x%lx\n", scsp, cptr_val(sslot), dcsp, cptr_val(dslot));
		} else
			printf("Failed to grant capability!!\n");
	}
	/* Release cnode Lock */
	__lcd_cnode_put(dcnode);

fail2:
	__lcd_cap_destroy_cspace(dcsp);
fail1:
	__lcd_cap_destroy_cspace(scsp);
	return ret;
}

int main()
{
	int ret;

	ret = testcase1();
	printf("\n\nTestcase : Capability Grant.\n");
	ret = testcase_grant();
}
