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
 */

#include <stdio.h>
#include <pthread.h>
#include "../include/internal.h"
#include "../include/types.h"
#include <string.h>

struct cspace *scsp;
struct cptr_cache *scache;

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
	int *i = (int *) arg;

	ret = __klcd_alloc_cptr(scache, &sslot);
	if (ret < 0) {
		printf("cptr aloocation failed\n");
		goto fail;
	}
	/* i may give strange values.
	 * Main focus is on sslot
         */
	printf("Thread[%d]: 0x%lx\n", *i, cptr_val(sslot));

	ret = insert(scsp, sslot);
	if (ret < 0) {
		printf("Insert failure 0x%lx\n", cptr_val(sslot));
		goto fail;
	}

fail:
	return;
}

int main()
{
	pthread_t thread[10];
	int i, ret, j;
	
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
	
	for (i=0; i<10; i++) {
		ret = pthread_create(&thread[i], NULL, thread1_func, (void *) &i);
		if (ret < 0) {
			perror("pthread create\n");
			goto fail1;
		}
	}
	
	for (j=0; j<10; j++) {
		ret = pthread_join(thread[j], NULL);
		if (ret < 0) {
			printf("Problem join %d\n", j);
		}
	}
fail1:
	__lcd_cap_destroy_cspace(scsp);
fail2:
	return ret;
}
