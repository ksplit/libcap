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
 * Grant [Done]
 * Revoke [Done]
 *
 * Test execution:
 *   ./<obj>/test/user/multi_thrd_cap
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
#include <string.h>
#include <errno.h>
#include "libcap.h"
#include "libcap_internal.h"
#include "libcap_types.h"

int stringobj_delete(struct cspace *cspace, struct cnode *cnode, void *object)
{
	CAP_DEBUG(0, "object = '%s'\n", (char *)object);
}

int stringobj_revoke(struct cspace *cspace, struct cnode *cnode, void *object)
{
	CAP_DEBUG(0, "object = '%s'\n", (char *)object);
}

int stringobj_type = 0;
struct cap_type_ops stringobj_ops = {
	.name = "stringobj",
	.delete = stringobj_delete,
	.revoke = stringobj_revoke,
};

#define BASE_THREAD_COUNT 10
#define THREAD_MULT 2000
#define THREAD_COUNT (BASE_THREAD_COUNT * THREAD_MULT)
#define SLOTS 500
#define STALL() usleep(10)

static struct cspace *scsp;
static struct cspace *dcsp;
static struct cptr_cache *scache;
static struct cptr_cache *dcache;
static cptr_t sslot_arr[SLOTS];
static cptr_t dslot_arr[SLOTS];
static int revoke_signal[SLOTS];
static int track = 0;
static pthread_t threads[THREAD_COUNT];
static cap_mutex_t global_user_lock;
static int global_stringobj_counter = 1;

int insert(struct cspace *csp, cptr_t slot)
{
	int ret;
	char *p;
	int next;

	cap_mutex_lock(&global_user_lock);
	next = global_stringobj_counter++;
	cap_mutex_unlock(&global_user_lock);

	p = malloc(32);
	if (!p) {
		perror("malloc\n");
		return 1;
	}
	/* using global could lead to race */
	snprintf(p, 32, "stringobj%d", next); 

	ret = cap_insert(csp, slot, p, stringobj_type);
	if (ret < 0) {
		CAP_ERR("cap insertion failed\n");
		return ret;
	}

	return ret;
}

void *thread1_func(void *arg)
{
	int ret;
	int slot;
	cptr_t sslot;

	/* Not protecting this variable i. */
	int *i = (int *)arg;

	ret = cptr_alloc(scache, &sslot);
	if (ret < 0) {
		printf("cptr aloocation failed\n");
		goto fail;
	}
	/* i may give strange values.
	 * Main focus is on sslot
	 */
	printf("Thread[%d] Inserting: 0x%lx\n", *i, cptr_val(sslot));

	ret = insert(scsp, sslot);
	if (ret < 0) {
		printf("Insert failure 0x%lx\n", cptr_val(sslot));
		goto fail;
	}

	cap_mutex_lock(&global_user_lock);
	if (track < SLOTS) {
	    slot = track++;
	}
	cap_mutex_unlock(&global_user_lock);

	if (track < SLOTS) {
		sslot_arr[slot] = sslot;
	    	printf("Thread[%d] Inserted: 0x%lx in slot %d\n",
		       *i, cptr_val(sslot), slot);
	}

 fail:
	return NULL;
}

void *thread_revoke(void* arg)
{
	int i = 0;
	int ret = 0;
	int n = 100;

	printf("Revoke called\n");

	if ((THREAD_COUNT - 4) < n)
	    n = THREAD_COUNT - 4;

	while (i < n) {
		printf("Thread Revoke : slot %d 0x%lx\n",
		       i, cptr_val(sslot_arr[i]));
		/* Wait for both insert and grant before revoke */
		if (!revoke_signal[i]) {
			printf("Thread Revoke : get on %i not done yet, stalling...\n",
				i);
			while (!revoke_signal[i]) {
			    STALL();
			}
			printf("Thread Revoke : unstalled cptr slot %i (0x%lx,0x%lx)\n",
			       i,cptr_val(sslot_arr[i]),cptr_val(dslot_arr[i]));
		}
		ret = cap_revoke(scsp, sslot_arr[i]);
		if (ret < 0)
			printf("Revoke failed\n");
		cap_delete(scsp, sslot_arr[i]);
		cptr_free(scache, sslot_arr[i]);
		sslot_arr[i] = CAP_CPTR_NULL;

		i++;
	}

	printf("Revoke finished\n");
}

void *thread_grant(void *arg) {
	int ret = 0;
	int i = 0;
	int n = 200;

	printf("Grant called\n");

	if ((THREAD_COUNT - 4) < n)
	    n = THREAD_COUNT - 4;

	while (i < n) {
		cptr_t dslot;
		ret = cptr_alloc(dcache, &dslot);
		if (ret < 0) {
			printf("CSPACE2 LCD alloc error\n");
		}
		if (cptr_is_null(sslot_arr[i])) {
			printf("Thread Grant : null cptr slot %d (0x%lx), stalling...\n",
			       i,cptr_val(sslot_arr[i]));
			while (cptr_is_null(sslot_arr[i])) {
			    STALL();
			}
			printf("Thread Grant : unstalled cptr slot %d (0x%lx)\n",
			       i,cptr_val(sslot_arr[i]));
		}
		ret = cap_grant(scsp, sslot_arr[i], dcsp, dslot);
		if (ret < 0) {
			printf("Granting capability failed\n");
		} else
			dslot_arr[i] = dslot;
		i++;
	}

	printf("Grant finished\n");
}

void *thread_get(void * arg) {
	int ret = 0;
	int i = 0;
	int n = 200;

	if ((THREAD_COUNT - 4) < n)
	    n = THREAD_COUNT - 4;

	while (i < n) {
		if (cptr_is_null(dslot_arr[i])) {
			printf("Thread Get : null cptr slot %d, stalling...\n",
			       i);
			while (cptr_is_null(dslot_arr[i])) {
			    STALL();
			}
			printf("Thread Get : unstalled cptr slot %d\n",
			       i);
		}
		ret = cap_cnode_verify(dcsp, dslot_arr[i]);
		if (ret < 0)
			CAP_ERR("Destination CSPACE Lookup failed\n");
		else
			printf("Lookup PASS\n");
		revoke_signal[i] = 1;
		i++;
	}
}

int main()
{
	int i, ret, j;
	int *it;

	/*
	 * Initialize libcap.
	 */
	ret = cap_init();
	if (ret < 0) {
		CAP_ERR("libcap init failed");
		goto out;
	}

	stringobj_type = cap_register_type(stringobj_type, &stringobj_ops);

	cap_mutex_init(&global_user_lock);

	scsp = cap_alloc_cspace();
	if (!scsp) {
		printf("Source Cspace allocation failed!\n");
		goto cap_exit;
	}

	ret = cap_init_cspace(scsp);
	if (ret < 0) {
		printf("Cspace Initialization failed\n");
		goto free_scspace;
	}

	/* 2nd CSPACE */	
	dcsp = cap_alloc_cspace();
	if (!dcsp) {
		printf("Destination Cspace allocation failed!\n");
		goto destroy_scspace;
	}

	ret = cap_init_cspace(dcsp);
	if (ret < 0) {
		printf("Cspace Initialization failed\n");
		goto free_dcspace;
	}

	ret = cptr_cache_alloc(&scache);
	if (ret < 0) {
		printf("cptr cache alloc failed\n");
		goto destroy_dcspace;
	}
	ret = cptr_cache_init(scache);
	if (ret < 0) {
		printf("cptr cache Initialization failed\n");
		goto free_scache;
	}

	ret = cptr_cache_alloc(&dcache);
	if (ret < 0) {
		printf("cptr cache alloc failed\n");
		goto destroy_scache;
	}
	ret = cptr_cache_init(dcache);
	if (ret < 0) {
		printf("cptr cache Initialization failed\n");
		goto free_dcache;
	}

	for (i = 0; i < SLOTS; i++) {
		sslot_arr[i] = CAP_CPTR_NULL;
		dslot_arr[i] = CAP_CPTR_NULL;
	}

	for (i = 0; i < THREAD_COUNT; i++) {
		if (i == 3 * THREAD_MULT) {
			ret = pthread_create(&threads[i], NULL, thread_grant,
					     (void *) &i);
		}
		else if (i == 5 * THREAD_MULT) {
			ret = pthread_create(&threads[i], NULL, thread_revoke,
					     (void *) &i);
		}
		else if (i == 9 * THREAD_MULT) {
			ret = pthread_create(&threads[i], NULL, thread_get,
					     (void *) &i);
		}
		else {
			it = malloc(sizeof(*it));
			*it = i;
			ret = pthread_create(&threads[i], NULL, thread1_func,
					     (void *)it);
		}
		if (ret < 0)
			printf("Error creating thread [%d]\n", i);
	}

	for (i = 0; i < THREAD_COUNT; i++) {
		ret = pthread_join(threads[i], NULL);
		if (ret < 0) {
			printf("Problem join %d\n", i);
		}
	}

destroy_dcache:
	cptr_cache_destroy(dcache);
free_dcache:
	cptr_cache_free(dcache);
destroy_scache:
	cptr_cache_destroy(scache);
free_scache:
	cptr_cache_free(scache);
destroy_dcspace:
	cap_destroy_cspace(dcsp);
free_dcspace:
	cap_free_cspace(dcsp);
destroy_scspace:
	cap_destroy_cspace(scsp);
free_scspace:
	cap_free_cspace(scsp);
cap_exit:
	cap_fini();
out:
	return ret;
}
