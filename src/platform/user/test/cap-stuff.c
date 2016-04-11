#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "libcap.h"
#include "libcap_internal.h"
#include "libcap_types.h"

int stringobj_delete(struct cnode *cnode)
{
	CAP_DEBUG(0, "object = '%s'\n", (char *)cap_cnode_object(cnode));
}

int stringobj_bin(struct cnode *src, struct cnode *cnode)
{
	CAP_DEBUG(0, "object_a = '%s', object_b = '%s'\n", 
				 (char *)cap_cnode_object(src), (char *) cap_cnode_object(src));
}

int stringobj_type = 0;
struct cap_type_ops stringobj_ops = {
	.name = "stringobj",
	.delete = stringobj_delete,
	.grant = stringobj_bin,
	.derive_src = stringobj_bin,
	.derive_dst = stringobj_bin,
};

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
	int ret = 0;
	struct cspace *csp = NULL;
	cptr_t slot_out, slot_out_orig;
	struct cptr_cache *cache;
	char *p;

	/* Initialize a cspace */
	csp = cap_alloc_cspace();
	if (!csp) {
		printf("bad alloc\n");
		goto out;
	}
	printf("\nTestCase : Cspace Initialization.\n");
	ret = cap_init_cspace(csp);
	if (ret < 0) {
		printf("Cspace Initialization Failed!!\n");
		goto free_cspace;
	} else
		printf("Cspace Initialization Passed Address:%p \n", csp);

	/* cptr cache intialization. This is totally users stuff */
	ret = cptr_cache_alloc(&cache);
	if (ret < 0) {
		printf("cptr cache alloc failed\n");
		goto destroy_cspace;
	}
	ret = cptr_cache_init(cache);
	if (ret < 0) {
		printf("cptr cache init failed\n");
		goto free_cache;
	}	

	ret = cptr_alloc(cache, &slot_out);
	p = strdup("testcase1");
	if (!p) {
		CAP_ERR("alloc failed");
		ret = -ENOMEM;
		goto destroy_cache;
	}

	/* Insert capability in cspace */
	printf("\nTestCase : Add Capability to Cspace.\n");
	ret = cap_insert(csp, slot_out, p, stringobj_type);

	if (ret < 0) {
		CAP_ERR("cap insertion failed\n");
		goto destroy_cache;
	}

	/* Verification if capability is properly inserted in the cspace. */
	ret = cap_cnode_verify(csp, slot_out);
	if (ret < 0) {
		CAP_ERR("Lookup failed");
		goto destroy_cache;
	} else
		printf("Capability Addition & Lookup Passed\n");

	/* Capability deletion from cspace. 
	 */
	printf("\nTestCase : Delete Capability from Cspace.\n");
	cap_delete(csp, slot_out);

	/*Lookup after deleting capability. It should Fail!!
	 */
	ret = cap_cnode_verify(csp, slot_out);
	if (ret < 0) {
		CAP_ERR("Lookup failed\n");
		printf("Capability Deletion Passed\n");
	}

	/* Free the cspace 
	 * Here we will destory the cspace.
	 * We will confirm the deletion after making a
	 * cap_insert call. If the call fails, that means
	 * cspace has been deleted successfully.
	 */
	printf("\nTestCase : Delete Cspace.\n");
	cap_destroy_cspace(csp);

	/* To check id cspace has been successfully destroyed,
	 * try to insert capability in cspace. Following call should
	 * return error.
	 */
	ret = cap_insert(csp, slot_out, p, stringobj_type);

	if (ret)
		printf("Cspace Deletion Passed\n");

destroy_cache:
	cptr_cache_destroy(cache);
free_cache:
	cptr_cache_free(cache);
destroy_cspace:
	cap_destroy_cspace(csp);
free_cspace:
	cap_free_cspace(csp);
out:
	return ret;
}

/*
 * Testcase to check the grant functionality
 */
int testcase_grant()
{
	int ret;
	struct cspace *scsp = NULL, *dcsp = NULL;
	cptr_t sslot, dslot;
	struct cptr_cache *scache, *dcache;
	char *p;

    cap_type_t type;

	/* Initialize Source cspace */
	scsp = cap_alloc_cspace();
	if (!scsp)
		return -1;
	ret = cap_init_cspace(scsp);
	if (ret < 0) {
		printf("Cspace Setup Failed\n");
		goto free_scspace;
	}
	printf("Source Cspace Initilaized: Address=%p\n", scsp);

	/* cptr cache intialization. This is totally users stuff */
	ret = cptr_cache_alloc(&scache);
	if (ret < 0) {
		printf("cache alloc failed\n");
		goto destroy_scspace;
	}
	ret = cptr_cache_init(scache);
	if (ret < 0) {
		printf("Cache Initilization failed\n");
		goto free_scache;
	}

	ret = cptr_alloc(scache, &sslot);
	if (ret < 0) {
		printf("cptr allocation Failed!!\n");
		goto destroy_scache;
	}
	p = strdup("testcase_grant");
	/* Insert capability in cspace */
	ret = cap_insert(scsp, sslot, p, stringobj_type);
	if (ret) {
		CAP_ERR("cap insertion failed\n");
		goto destroy_scache;
	}
	printf("Added capability [%p] to Source cspace\n", p);

	/* Setup destination cspace */
	dcsp = cap_alloc_cspace();
	if (!dcsp)
		goto destroy_scache;
	ret = cap_init_cspace(dcsp);
	if (ret < 0) {
		printf("Cspace Setup Failed\n");
		goto free_dcspace;
	}
	printf("Destination Cspace Initilaized: Address=%p\n", dcsp);

	ret = cptr_cache_alloc(&dcache);
	if (ret < 0) {
		printf("cache alloc failed\n");
		goto destroy_dcspace;
	}
	ret = cptr_cache_init(dcache);
	if (ret < 0) {
		printf("Cache Initilization failed\n");
		goto free_dcache;
	}

	ret = cptr_alloc(dcache, &dslot);
	if (ret < 0) {
		printf("cptr allocation Failed!!\n");
		goto destroy_dcache;
	}

	ret = cap_grant(scsp, sslot, dcsp, dslot, &type);
	if (ret < 0) {
		printf("Granting capability failed\n");
		goto destroy_dcache;
	}

	ret = cap_cnode_verify(dcsp, dslot);
	if (ret < 0) {
		CAP_ERR("Lookup failed\n");
		goto destroy_dcache;
	} else {
		printf("Capability granted successfully from Cspace[%p] at slot 0x%lx \
				to Cspace[%p] at slot 0x%lx\n", scsp, cptr_val(sslot),
				dcsp, cptr_val(dslot));
	}


destroy_dcache:
	cptr_cache_destroy(dcache);
free_dcache:
	cptr_cache_free(dcache);
destroy_dcspace:
	cap_destroy_cspace(dcsp);
free_dcspace:
	cap_free_cspace(dcsp);
destroy_scache:
	cptr_cache_destroy(scache);
free_scache:
	cptr_cache_free(scache);
destroy_scspace:
	cap_destroy_cspace(scsp);
free_scspace:
	cap_free_cspace(scsp);
	return ret;
}

/*
 * capability insert
 */
int insert(struct cspace *csp, cptr_t slot)
{
	int ret = 0;
	char *p;

	p = malloc(5 * sizeof(*p));
	if (!p) {
		perror("malloc\n");
		ret = -1;
		goto fail;
	}
	snprintf(p,5,"icap");

	ret = cap_insert(csp, slot, p, stringobj_type);
	if (ret < 0) {
		CAP_ERR("cap insertion failed\n");
	}

fail:
	return ret;
}

/*
 *Capability grant
 */
int grant(struct cspace *scsp, struct cspace *dcsp, cptr_t sslot, cptr_t dslot) {
	int ret = 0;

    cap_type_t type;
	ret = cap_grant(scsp, sslot, dcsp, dslot, &type);
	if (ret < 0)
		printf("Granting capability failed\n");

	return ret;
}

/*
 *Get Cnode
 */
int get_cnode(struct cspace *csp, cptr_t sslot) {
	int ret = 0;

	ret = cap_cnode_verify(csp, sslot);
	if (ret < 0)
		CAP_ERR("Destination CSPACE Lookup failed\n");
	
	return ret;
}

/* 
 * Capability Revoke
 */
int do_revoke(struct cspace *csp, cptr_t sslot, struct cptr_cache *scache) {
	int ret = 0;

	ret = cap_revoke(csp, sslot);
	if (ret < 0)
		printf("Revoke failed\n");
	cptr_free(scache, sslot);

	return ret;
}

/*
 * This testcase is checking capability revoke function.
 * Here a capability is inserted in CSPACE A and granted to CSPACE B.
 * Capability is then revoked from CSPACE A.
 * Check is performed if Capability is still present in CSPACE B.
 * It should not be present in CSPACE B.
 */
int testcase_revoke() {
	int ret = 0;
	struct cspace *scsp = NULL, *dcsp = NULL;
	struct cptr_cache *scache, *dcache;
	cptr_t sslot, dslot;

	printf("\nTestcase : Capability Revocation\n");
	/* 1st CSPACE */
	scsp = cap_alloc_cspace();
		if (!scsp) {
				perror("Source Cspace allocation failed\n");
				goto out;
		}
		ret = cap_init_cspace(scsp);
		if (ret < 0) {
				printf("Cspace Initialization failed\n");
				goto free_scspace;
		}

	ret = cptr_cache_alloc(&scache);
	if (ret < 0) {
		printf("cache alloc failed\n");
		goto destroy_scspace;
	}
		ret = cptr_cache_init(scache);
		if (ret < 0) {
				printf("cptr cache Initialization failed\n");
				goto free_scache;
		}

	/* 2nd CSPACE */
		dcsp = cap_alloc_cspace();
		if (!dcsp) {
				perror("malloc cspace\n");
				goto destroy_scache;
		}
		ret = cap_init_cspace(dcsp);
		if (ret < 0) {
				printf("Cspace Initialization failed\n");
				goto free_dcspace;
		}
	ret = cptr_cache_alloc(&dcache);
	if (ret < 0) {
		printf("cache alloc failed\n");
		goto destroy_dcspace;
	}
		ret = cptr_cache_init(dcache);
		if (ret < 0) {
				printf("cptr cache Initialization failed\n");
				goto free_dcache;
		}

	ret = cptr_alloc(scache, &sslot);
		if (ret < 0) {
				printf("cptr aloocation failed\n");
				goto destroy_dcache;
		}
	ret = cptr_alloc(dcache, &dslot);
	if (ret < 0) {
				printf("cptr aloocation failed\n");
		goto destroy_dcache;
	}

	ret = insert(scsp, sslot);
	if (ret < 0)
		goto destroy_dcache;
	ret = grant(scsp, dcsp, sslot, dslot);
	if (ret < 0)
		goto destroy_dcache;
	ret = do_revoke(scsp, sslot, scache);
	if (ret < 0)
		goto destroy_dcache;
	ret = cap_cnode_verify(dcsp, dslot);
	if (ret < 0) {
		printf("\nTestcase Capability Revocation Passed\n");
		goto destroy_dcache;
	}
	printf("\nTestcase capability Revocation Failed\n");

destroy_dcache:
	cptr_cache_destroy(dcache);
free_dcache:
	cptr_cache_free(dcache);
destroy_dcspace:
	cap_destroy_cspace(dcsp);
free_dcspace:
	cap_free_cspace(dcsp);
destroy_scache:
	cptr_cache_destroy(scache);
free_scache:
	cptr_cache_free(scache);
destroy_scspace:
	cap_destroy_cspace(scsp);
free_scspace:
	cap_free_cspace(scsp);
out:
	return ret;
}

int main()
{
	int ret = 0;

	/*
	 * Initialize libcap.
	 */
	ret = cap_init();
	if (ret < 0) {
		CAP_ERR("libcap init failed");
		return ret;
	}

	stringobj_type = cap_register_type(stringobj_type, &stringobj_ops);

	ret = testcase1();
	ret = testcase_grant();
	ret = testcase_revoke();

	cap_fini();

	return ret;
}
