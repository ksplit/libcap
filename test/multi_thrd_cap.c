/*
 * multi_thrd_cap.c - libcap testing using multiple threads
 *
 * Authors:
 *	pankajk@cs.utah.edu 
 *
 * Program to test libcap for multiple threads execution.
 * Presently testing it for 10 threads.
 * 
 * Operations list:
 * Accessing cspace by multiple threads [Done]
 * Accessing cptr cache by multiple threads [Done]
 * capability insertion by multiple threads [Done]
 * Grant [Todo]
 * Revoke [Todo]
 *
 * Test execution:
 * cd libcap; make
 * cd libacp/test; make
 * ./libcap/test/mult
 *
 * Modification:
 * CSPACE count : 2
 * Runing threads : 20,000
 * Capabilities Inserted : 20,000
 * Granted to other cspace : 200
 * Revoked : 100
 * Lookup : 200(explicit), Otherwise: 20,500
 *
 */

#include <stdio.h>
#include <pthread.h>
#include "../include/internal.h"
#include "../include/types.h"
#include <string.h>

struct cspace *scsp;
struct cspace *dcsp;
struct cptr_cache *scache;
struct cptr_cache *dcache;
cptr_t sslot_arr[500];
cptr_t dslot_arr[500];
int track = 0;

int insert (struct cspace *csp, cptr_t slot) {
	int ret;
	void *p;

	p = malloc(1 * sizeof(*p));
	if (!p) {
		perror("malloc\n");
		return 1;
	}

	ret = __lcd_cap_insert(csp, slot, p, LCD_CAP_TYPE_PAGE);
	if (ret < 0) {
		LCD_ERR("cap insertion failed\n");
		return ret;
	}

	return ret;
}

void *thread1_func(void *arg)
{
	int ret;
	cptr_t sslot;

	/* Not protecting this variable i. */
	ret = __klcd_alloc_cptr(scache, &sslot);
	if (ret < 0) {
		printf("cptr aloocation failed\n");
		goto fail;
	}
	/* i may give strange values.
	 * Main focus is on sslot
         */
	printf("Thread Inserting: 0x%lx\n", cptr_val(sslot));

	ret = insert(scsp, sslot);
	if (ret < 0) {
		printf("Insert failure 0x%lx\n", cptr_val(sslot));
		goto fail;
	}
	if (track < 500) {
		sslot_arr[track] = sslot;
		track++;
	}
fail:
	return;
}

void *thread_revoke(void* arg) {
	printf("\nRevoke Called\n");
	int i = 0;
	int ret = 0;

	while (i < 100) {
		printf("Thread Revoke : 0x%lx\n", cptr_val(sslot_arr[i]));
		ret = __lcd_cap_revoke(scsp, sslot_arr[i]);
		if (ret < 0)
			printf("Revoke failed\n");
		__lcd_cap_delete(scsp, sslot_arr[i]);
		if (ret < 0)
			printf("Delete failed\n");
		__klcd_free_cptr(scache, sslot_arr[i]);

		i++;
	}
}

void *thread_grant(void *arg) {
	int ret = 0;
	int i = 0;
	printf("Grant called\n");
	while(i < 200) {
		cptr_t dslot;
		ret = __klcd_alloc_cptr(dcache, &dslot);
		if (ret < 0) {
			printf("CSPACE2 LCD alloc error\n");
		}
		ret = libcap_grant_capability((void *)scsp, (void *)dcsp, sslot_arr[i], dslot);
		if (ret < 0) {
			printf("Granting capability failed\n");
		} else
			dslot_arr[i] = dslot;
		i++;
	}
}

void *thread_get(void * arg) {
	int ret = 0;
	int i = 0;
	while(i < 200) {
		struct cnode *dcnode;
		ret = __lcd_cnode_get(dcsp, dslot_arr[i], &dcnode);
		if (ret < 0) {
			LCD_ERR("Destination CSPACE Lookup failed\n");
		} else {
			printf("Lookup PASS\n");
			/* Release cnode Lock */
			__lcd_cnode_put(dcnode);
		}
		i++;
	}
}

int main()
{
	pthread_t thread[20000];
	int i, ret, j;

	/* 1st CSPACE */	
	scsp = malloc(1 * sizeof(*scsp));
	if (!scsp) {
		perror("malloc cspace\n");
		exit(1);
	}

	ret = __lcd_cap_init_cspace(scsp);
	if (ret < 0) {
		printf("Cspace Initialization failed\n");
		goto fail2;
	}

	ret = cptr_cache_init(&scache);
	if (ret < 0) {
		printf("cptr cache Initialization failed\n");
		goto fail1;
	}

	/* 2nd CSPACE */	
	dcsp = malloc(1 * sizeof(*dcsp));
	if (!dcsp) {
		perror("malloc cspace\n");
		exit(1);
	}

	ret = __lcd_cap_init_cspace(dcsp);
	if (ret < 0) {
		printf("Cspace Initialization failed\n");
		goto fail2;
	}

	ret = cptr_cache_init(&dcache);
	if (ret < 0) {
		printf("cptr cache Initialization failed\n");
		goto fail;
	}

	for (i=0; i<20000; i++) {
		if (i == 3000) {
			ret = pthread_create(&thread[i], NULL, thread_grant, (void *) &i);
		} else if (i == 5000) {
			ret = pthread_create(&thread[i], NULL, thread_revoke, (void *) &i);
		} else if (i == 9000) {
			ret = pthread_create(&thread[i], NULL, thread_get, (void *) &i);
		} else {
			ret = pthread_create(&thread[i], NULL, thread1_func, (void *) &i);
		} if (ret < 0) {
			printf("pthread create\n");
		}
	}

	for (i=0; i<20000; i++) {
		ret = pthread_join(thread[i], NULL);
		if (ret < 0) {
			printf("Problem join %d\n", i);
		}
	} 
fail:
	__lcd_cap_destroy_cspace(dcsp);
fail1:
	__lcd_cap_destroy_cspace(scsp);
fail2:
	return ret;
}
