/**
 * cap.c - capability subsystem
 *
 * Authors:
 *     Muktesh Khole <mukteshkhole86@gmail.com>
 *     Anton Burtsev <aburtsev@flux.utah.edu>
 *     Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 * See Documentation/lcd-domains/cap.txt for extensive info.
 */
#include "libcap.h"
#include "libcap_types.h"
#include "libcap_internal.h"

struct cdt_cache {
	cap_mutex_t lock;
	cap_cache_t *cdt_root_cache;
};

static struct cdt_cache cdt_cache;
static cap_mutex_t global_lock;
static struct cap_type_ops cap_types[CAP_TYPE_MAX] = {
	{"none", NULL, NULL,}, {"invalid", NULL, NULL},
	{"free", NULL, NULL}, {"cnode", NULL, NULL},
};

/*
 * This is used in a hack to make the cnode table slab caches
 * work. See init cspace routine.
 */
static unsigned long long cspace_id = 0;

int cap_init(void)
{
	/*
	 * Initialize cdt cache
	 */
	cdt_cache.cdt_root_cache = cap_cache_create(cdt_root_node);
	if (!cdt_cache.cdt_root_cache) {
		CAP_ERR("failed to initialize cdt_root_node allocator");
		return -ENOMEM;
		return -1;
	}
	cap_mutex_init(&cdt_cache.lock);
	cap_mutex_init(&global_lock);
	memset(cap_types, 0, sizeof(cap_types));

	return 0;
}

void cap_fini(void)
{
	int i;
	/*
	 * Destroy cdt cache
	 */
	cap_cache_destroy(cdt_cache.cdt_root_cache);
	/*
	 * Free up any strdup'd names in the cap_types array
	 */
	for (i = CAP_TYPE_FIRST_NONBUILTIN; i < CAP_TYPE_MAX; ++i)
		if (cap_types[i].name)
			free(cap_types[i].name);
}

cap_type_t cap_register_type(cap_type_t type, const struct cap_type_ops *ops)
{
	int i, ret;

	cap_mutex_lock(&global_lock);
	if (type <= 0) {
		for (i = CAP_TYPE_FIRST_NONBUILTIN; i < CAP_TYPE_MAX; ++i) {
			if (cap_types[i].name)
				continue;
			else {
				break;
			}
		}
	} else
		i = type;

	if (i >= CAP_TYPE_MAX) {
		CAP_ERR("not enough types available!");
		ret = -ENOBUFS;
		goto out;
	} else if (cap_types[i].name) {
		CAP_ERR("cap type %d already in use", type);
		ret = -EADDRINUSE;
		goto out;
	} else {
		cap_types[i].name = strdup(ops->name);
		cap_types[i].delete = ops->delete;
		cap_types[i].revoke = ops->revoke;
		ret = i;
		goto out;
	}
 out:
	cap_mutex_unlock(&global_lock);
	return ret;
}

/**
 * Allocates a new cdt root node using the cdt cache.
 */
struct cdt_root_node *get_cdt_root(void)
{
	int ret;
	struct cdt_root_node *cdt_node = NULL;

	ret = cap_mutex_lock_interruptible(&cdt_cache.lock);
	if (ret) {
		CAP_ERR("mutex lock interrupted");
		goto out;
	}
	cdt_node = cap_cache_alloc(cdt_cache.cdt_root_cache);
	cdt_node->state = ALLOCATION_VALID;
	cap_mutex_init(&cdt_node->lock);
	cap_mutex_unlock(&cdt_cache.lock);

 out:
	return cdt_node;
}

void free_cdt_root(struct cdt_root_node *cdt_node)
{
	int ret;

	ret = cap_mutex_lock_interruptible(&cdt_cache.lock);
	if (ret) {
		CAP_ERR("interrupted");
		goto out;
	}

	cdt_node->state = ALLOCATION_REMOVED;
	cap_cache_free(cdt_cache.cdt_root_cache, cdt_node);
	cap_mutex_unlock(&cdt_cache.lock);

 out:
	return;
}

/* CSPACES -------------------------------------------------- */

static int make_empty_cnode_table(struct cspace *cspace, uint8_t level,
				  struct cnode_table **new_out)
{
	struct cnode_table *new;
	int i;

	/*
	 * Allocate
	 */
	new = cap_cache_zalloc(cspace->cnode_table_cache);
	if (!new)
		goto fail1;
	/*
	 * Mark all cnodes in new table as free, and init spin lock.
	 * We delay some of the other set up until the cnode is
	 * actually used.
	 */
	for (i = 0; i < CAP_CSPACE_CNODE_TABLE_SIZE; i++) {
		new->cnode[i].type = CAP_TYPE_FREE;
		INIT_LIST_HEAD(&new->cnode[i].children);
		INIT_LIST_HEAD(&new->cnode[i].siblings);
		cap_mutex_init(&new->cnode[i].lock);
	}

	new->table_level = level;

	/*
	 * Add to cspace's list of cnode tables. (This is used when we
	 * tear down the whole cspace. For now, we don't greedily free
	 * cnode tables as they become empty, so we don't delete them from
	 * the list until the cspace is destroyed.)
	 */
	list_add(&new->table_list, &cspace->table_list);

	*new_out = new;

	return 0;
 fail1:
	return -ENOMEM;
}

inline struct cspace* cap_alloc_cspace(void) {
    return cap_zalloc(1, sizeof(struct cspace));
}

inline void cap_free_cspace(struct cspace *cspace) { cap_free(cspace); }

/**
 * Initializes the cspace's fields.
 */
int cap_init_cspace(struct cspace *cspace)
{
	int ret;
	char name[32];

	ret = cap_mutex_init(&cspace->lock);
	if (ret) {
		CAP_ERR("mutex initialization failed");
		return ret;
	}

	/*
	 * Initialize the cnode table cache. We can't use the
	 * KMEM_CACHE macro because we need to use unique names. This
	 * is kind of hacky right now. (If you don't use a unique name,
	 * you might get an error/crash when you destroy the kmem cache
	 * for multiple lcd's. This is because slabs are tied to sysfs, and
	 * it complains when it tries to remove slabs with the same name.)
	 */
	cap_mutex_lock(&global_lock);
	snprintf(name, 32, "cspace%llu", (unsigned long long)cspace_id);
	cspace->cnode_table_cache = cap_cache_create2(cnode_table, name);
	if (!cspace->cnode_table_cache) {
		CAP_ERR("failed to allocate cnode_table slab");
		return -ENOMEM;
	}

	/*
	 * Initialize list of cnode tables
	 */
	INIT_LIST_HEAD(&cspace->table_list);

	/*
	 * Initialize the root cnode table
	 */
	ret = make_empty_cnode_table(cspace, 0, &cspace->cnode_table);
	if (ret) {
		cap_cache_destroy(cspace->cnode_table_cache);
		cspace->cnode_table_cache = NULL;
		CAP_ERR("error initializing root cnode table");
		return ret;
	}

	cspace->state = ALLOCATION_VALID;

	cspace_id++;

	/* Don't worry about holding the global lock this long; almost
	 * nothing uses it.
	 */
	cap_mutex_unlock(&global_lock);

	return 0;
}

inline void cap_cspace_setowner(struct cspace *cspace, void * owner) {
    cspace->owner = owner;
}
inline void* cap_cspace_getowner(struct cspace *cspace) { return cspace->owner; }

static int update_cnode_table(struct cspace *cspace,
			      struct cnode_table *old, unsigned long level_id,
			      bool alloc, struct cnode_table **new)
{
	unsigned long index;
	int ret;
	/*
	 * The first half of the slots contain caps, the second half table
	 * pointers. Skip over cap slots by adding half the number of slots
	 * to level_id.
	 */
	index = level_id + (CAP_CSPACE_CNODE_TABLE_SIZE >> 1);

	if (old->cnode[index].type == CAP_TYPE_CNODE) {
		/*
		 * Slot contains a cnode that points to the next table.
		 */
		*new = old->cnode[index].object;

		return 0;	/* signal we are not done yet */

	} else if (old->cnode[index].type == CAP_TYPE_FREE && alloc) {
		/*
		 * The cnode is free, and we can alloc.
		 *
		 * Allocate and init a new cnode table
		 */
		ret = make_empty_cnode_table(cspace, old->table_level + 1, new);
		if (ret) {
			CAP_ERR("Error making empty cnode table\n");
			return ret;
		}
		/*
		 * Set up cnode that points to it
		 */
		old->cnode[index].type = CAP_TYPE_CNODE;
		old->cnode[index].object = *new;

		return 0;	/* signal we are not done yet */
	} else {
		/*
		 * cnode free, invalid, etc.
		 */
		CAP_DEBUG(CAP_DEBUG_ERR,
			"Error in cspace traversal: cnode contains%s, and we are%s trying to alloc\n",
			old->cnode[level_id].type == CAP_TYPE_CNODE ?
			" a pointer to the next level" : " has unexpected type (not a pointer to a cnode in the next level)",
			alloc ? "" : " not");
		return -EINVAL;	/* signal error in look up */
	}
}

static int find_cnode(struct cspace *cspace, struct cnode_table *old,
		      unsigned long level_id, bool alloc, struct cnode **cnode)
{
	/*
	 * The first slots contain capabilities
	 */
	if (old->cnode[level_id].type != CAP_TYPE_FREE && !alloc) {
		/*
		 * cnode contains an object. We want to catch the case when
		 * we expected to alloc.
		 */
		*cnode = &old->cnode[level_id];

		return 1;	/* signal we found the slot and are done */

	} else if (old->cnode[level_id].type == CAP_TYPE_FREE && alloc) {
		/*
		 * cnode is empty, but we expected that (alloc is true).
		 *
		 * Initialize it.
		 */
		*cnode = &old->cnode[level_id];
		cap_mutex_init(&(*cnode)->lock);
		(*cnode)->cspace = cspace;

		return 1;	/* signal we found the slot and are done */
	} else {
		/*
		 * invalid indexing, etc.
		 */
		CAP_DEBUG(CAP_DEBUG_ERR,
			"Error in lookup: cnode is %s, and we are%s trying to alloc\n",
			old->cnode[level_id].type == CAP_TYPE_FREE ?
				"free" : "occupied",
			alloc ? "" : " not");
		return -EINVAL;	/* signal an error in look up */
	}
}

static int get_level_index(int table_level, cptr_t c, unsigned long *level_id)
{
	/*
	 * Calculate the depth of the index
	 */
	if (cap_cptr_level(c) == table_level) {
		/*
		 * We're at the final level - we're done, and need to look in 
		 * the cap slots in the cnode table
		 */
		*level_id = cap_cptr_slot(c);
		return 0;	/* signal no more levels to traverse */
	} else {
		/*
		 * More levels to go; determine index of next table to
		 * look at
		 */
		*level_id = cap_cptr_fanout(c, table_level);
		return 1;	/* signal more levels to traverse */
	}
}

static int walk_one_level(struct cspace *cspace, cptr_t c, bool alloc,
			  struct cnode_table *old, struct cnode_table **new,
			  struct cnode **cnode)
{
	int more_levels;
	unsigned long level_id;

	more_levels = get_level_index(old->table_level, c, &level_id);
	if (more_levels)
		return update_cnode_table(cspace, old, level_id, alloc, new);
	else
		return find_cnode(cspace, old, level_id, alloc, cnode);
}

/**
 * Finds the cnode in cspace indexed by cptr c. If alloc is true,
 * allocates cnode tables on the fly while looking up c.
 *
 * ** Expects the cspace to be locked by the caller. **
 */
static int __cap_cnode_lookup(struct cspace *cspace, cptr_t c, bool alloc,
			      struct cnode **cnode)
{

	int ret;
	struct cnode_table *old;
	struct cnode_table *new;

	/*
	 * If cptr is null, fail
	 */
	if (cptr_is_null(c)) {
		CAP_DEBUG(CAP_DEBUG_MSG, "cptr is null, lookup aborted\n");
		return -EINVAL;
	}

	/*
	 * Initialize to root cnode table
	 */
	old = cspace->cnode_table;
	do {
		/*
		 * Walk one level. Table gets updated to the next level's
		 * table, and cnode will be non-NULL and point to the final
		 * cnode when we get there.
		 *
		 * walk_one_level returns 1 when we find the cnode, 0 when we
		 * should keep going, and < 0 on error.
		 */
		ret = walk_one_level(cspace, c, alloc, old, &new, cnode);
		old = new;
	} while (!ret);

	/*
	 * only return non zero if we had an error
	 */
	return (ret < 0 ? ret : 0);
}

static int __cap_cnode_get(struct cspace *cspace, cptr_t c,
			   bool alloc, struct cnode **cnode)
{
	int ret;

	/*
	 * Look up and lock cnode
	 */
	ret = cap_mutex_lock_interruptible(&cspace->lock);
	if (ret) {
		CAP_ERR("mutex lock interrupted");
		goto fail1;
	}

	if (cspace->state != ALLOCATION_VALID) {
		CAP_ERR("Cspace state is not valid, state is %d\n",
			cspace->state);
		ret = -EIDRM;
		goto fail2;
	}
	ret = __cap_cnode_lookup(cspace, c, alloc, cnode);
	if (ret) {
		CAP_DEBUG(CAP_DEBUG_MSG,
			"cnode lookup failed with ret = %d\n", ret)
		goto fail2;
	}

	ret = cap_mutex_lock_interruptible(&(*cnode)->lock);
	if (ret) {
		CAP_ERR("interrupted");
		goto fail2;
	}

	cap_mutex_unlock(&cspace->lock);

	return 0;

 fail2:
	cap_mutex_unlock(&cspace->lock);
 fail1:
	return ret;
}

int cap_cnode_get(struct cspace *cspace, cptr_t c, struct cnode **cnode)
{
	return __cap_cnode_get(cspace, c, false, cnode);
}

void cap_cnode_put(struct cnode *cnode)
{
	cap_mutex_unlock(&cnode->lock);
}

void* cap_cnode_object(struct cnode *cnode) { return cnode->object; }
cap_type_t cap_cnode_type(struct cnode *cnode) { return cnode->type; }
struct cspace * cap_cnode_cspace(struct cnode *cnode) { return cnode->cspace; }

void* cap_cnode_metadata(struct cnode *cnode)
{
	return cnode->metadata;
}

void cap_cnode_set_metadata(struct cnode *cnode, void *metadata)
{
	cnode->metadata = metadata;
}

int cap_cnode_verify(struct cspace *cspace, cptr_t c)
{
	struct cnode *cnode;
	int ret;

	ret = cap_cnode_get(cspace, c, &cnode);
	if (ret == 0)
		cap_cnode_put(cnode);
	
	return ret;
}

cptr_t cap_cnode_cptr(struct cnode *cnode) { return cnode->cptr; }

int cap_insert(struct cspace *cspace, cptr_t c, void *object, cap_type_t type)
{
	struct cnode *cnode;
	int ret;

	if (type < CAP_TYPE_FIRST_NONBUILTIN || type >= CAP_TYPE_MAX) {
		CAP_ERR("unregistered type %d -- BUG!", type);
		return -EADDRNOTAVAIL;
	}

	/*
	 * Get cnode
	 */
	ret = __cap_cnode_get(cspace, c, true, &cnode);
	if (ret) {
		CAP_ERR("Getting cnode for cptr 0x%lx\n", cptr_val(c));
		return ret;
	}
	/*
	 * Set data
	 */
	cnode->cspace = cspace;
	cnode->object = object;
	cnode->type = type;
	cnode->cptr = c;
	/*
	 * Set up cdt
	 */
	cnode->cdt_root = get_cdt_root();
	cnode->cdt_root->cnode = cnode;
	/*
	 * Release cnode
	 */
	cap_cnode_put(cnode);

	return 0;
}

static void cap_notify_delete(struct cspace *cspace, struct cnode *cnode)
{
	cap_type_t type = cnode->type;

	if (type >= CAP_TYPE_FIRST_NONBUILTIN && type < CAP_TYPE_MAX
	    && cap_types[type].name) {
		if (cap_types[type].delete)
			cap_types[type].delete(cspace, cnode, cnode->object);
	} else {
		CAP_ERR("invalid object type %d -- BUG!", type);
	}
}

static void cap_notify_revocation(struct cspace *cspace, struct cnode *cnode)
{
	cap_type_t type = cnode->type;

	if (type >= CAP_TYPE_FIRST_NONBUILTIN && type < CAP_TYPE_MAX
	    && cap_types[type].name) {
		if (cap_types[type].revoke)
			cap_types[type].revoke(cspace, cnode, cnode->object);
	} else {
		CAP_ERR("invalid object type %d -- BUG!", type);
	}
}

/**
 * Does actual removal from cdt. Returns non-zero if cnode is the last one
 * in the cdt.
 *
 * ** Expects cnode and cdt_root to be locked, in that order. **
 */
static int do_delete_from_cdt(struct cnode *cnode,
			      struct cdt_root_node *cdt_root)
{
	int last_node = 0;
	/*
	 * Make the cnode's children the children of cnode's parent by
	 * putting them in the cnode's siblings list. (Note that
	 * list_splice does the right thing when children or siblings is
	 * empty.)
	 */
	list_splice_init(&cnode->children, &cnode->siblings);
	/*
	 * If cnode was the root cnode of the cdt, update the cdt's root.
	 */
	if (cdt_root->cnode == cnode) {
		/*
		 * See if anyone is in siblings - this will include cnode's
		 * children since we spliced lists. list_first_entry will
		 * look at the next list item, not the current cnode.
		 */
		if (!list_empty(&cnode->siblings)) {
			cdt_root->cnode = list_first_entry(&cnode->siblings,
							   struct cnode,
							   siblings);
		} else {
			last_node = 1;
			cdt_root->cnode = NULL;
		}
	}
	/*
	 * Remove cnode from list of siblings (won't break if siblings is
	 * empty).
	 */
	list_del_init(&cnode->siblings);

	return last_node;
}

/**
 * Tries to lock cdt and remove cnode from it. Returns non-zero if 
 * cnode successfully deleted.
 */
static int try_delete_cnode(struct cspace *cspace, struct cnode *cnode)
{
	int last_node;
	struct cdt_root_node *cdt_node;

	/*
	 * Try to lock the cdt
	 */
	if (!cap_mutex_trylock(&cnode->cdt_root->lock)) {
		/*
		 * Tell caller to retry
		 */
		return 0;
	}
	/*
	 * Get the cdt
	 */
	cdt_node = cnode->cdt_root;
	/*
	 * Delete the cnode from the cdt
	 */
	last_node = do_delete_from_cdt(cnode, cdt_node);
	if (last_node)
		cdt_node->state = ALLOCATION_MARKED_FOR_DELETE;
	/*
	 * Unlock cdt
	 */
	cap_mutex_unlock(&cdt_node->lock);

	/* Order of what follows is important */

	/*
	 * Update microkernel state to reflect rights change (e.g., if we're
	 * deleting a cnode for an endpoint, we need to ensure the lcd isn't
	 * in the endpoint's queues).
	 */
	cap_notify_revocation(cspace, cnode);

	if (last_node) {
		/*
		 * No lcd's have a reference to the object anymore. Time to
		 * tear it down.
		 *
		 * Delete the cdt
		 */
		free_cdt_root(cdt_node);
		/*
		 * Tear down the object.
		 *
		 * SPECIAL CASE: If deleting an lcd, and the calling lcd is
		 * the lcd to be deleted, this call does not return.
		 */
		cap_notify_delete(cspace, cnode);
	}

	/*
	 * Mark cnode as free, null out fields.
	 *
	 * XXX: We could possibly free up the cnode table if all of its cnodes
	 * are free. For now, they just hang around and will be freed when
	 * the whole cspace is torn down.
	 */

	cnode->type = CAP_TYPE_FREE;
	cnode->object = NULL;
	cnode->cdt_root = NULL;
	cnode->metadata = NULL;
	/*
	 * Signal we are done
	 */
	return 1;
}

void cap_delete(struct cspace *cspace, cptr_t c)
{
	struct cnode *cnode;
	int done;
	int ret;

	/*
	 * Fail for null
	 */
	if (cptr_is_null(c)) {
		CAP_ERR("trying to delete null cptr");
		return;
	}

	/*
	 * This entire thing has to go in a loop - we need to release
	 * the lock on cnode and try again until we can lock the cdt.
	 */
	do {
		/*
		 * Look up cnode
		 */
		ret = cap_cnode_get(cspace, c, &cnode);
		if (ret) {
			CAP_ERR("error getting cnode");
			goto out1;
		}

		/*
		 * If the cnode is already marked as free, just return.
		 *
		 * (The cnode may not have been free the first time we tried
		 * to delete it, but when we reattempted, it was freed by 
		 * someone else.)
		 */
		if (cnode->type == CAP_TYPE_FREE) {
			CAP_MSG("cnode already free");
			goto out2;
		}

		/*
		 * If cnode is invalid or has type cnode (points to another 
		 * cnode table), ignore and return.
		 */
		if (cnode->type == CAP_TYPE_INVALID ||
		    cnode->type == CAP_TYPE_CNODE) {
			CAP_MSG("ignoring attempt to delete invalid cnode");
			goto out2;
		}

		/*
		 * Delete the cnode
		 */
		done = try_delete_cnode(cspace, cnode);

		/*
		 * Release cnode
		 */
		cap_cnode_put(cnode);

		if (!done) {
			/*
			 * Someone else is using the cdt; wait 1 ms for him
			 * to finish.
			 */
			msleep(1);
		}

	} while (!done);

	return;

 out2:
	cap_cnode_put(cnode);
 out1:
	return;
}

static int try_grant(struct cspace *cspacedst, struct cnode *cnodesrc,
		     struct cnode *cnodedst)
{
	/*
	 * Try to lock the cdt containing source cnode (dest cnode should
	 * not be in a cdt)
	 */
	if (!cap_mutex_trylock(&cnodesrc->cdt_root->lock)) {
		/*
		 * Tell caller to retry
		 */
		return 0;
	}

	/*
	 * Add dest cnode to source's children in cdt
	 */
	list_add(&cnodedst->siblings, &cnodesrc->children);

	/*
	 * Unlock cdt
	 */
	cap_mutex_unlock(&cnodesrc->cdt_root->lock);

	/*
	 * Set dest cnode's fields with source's
	 */
	cnodedst->type = cnodesrc->type;
	cnodedst->object = cnodesrc->object;
	cnodedst->cspace = cspacedst;
	cnodedst->cdt_root = cnodesrc->cdt_root;

	return 1;
}

int cap_grant(struct cspace *cspacesrc, cptr_t c_src,
	      struct cspace *cspacedst, cptr_t c_dst)
{
	struct cnode *cnodesrc, *cnodedst;
	int done;
	int ret;

	/*
	 * Fail for null
	 */
	if (cptr_is_null(c_src) || cptr_is_null(c_dst)) {
		CAP_ERR("trying to grant with a null cptr");
		return -EINVAL;
	}

	/*
	 * This entire thing has to go in a loop - we need to release
	 * the lock on (at least) the source cnode and try again until we can 
	 * lock the cdt containing the source cnode.
	 */

	do {
		/*
		 * Look up source
		 */
		ret = __cap_cnode_get(cspacesrc, c_src, false, &cnodesrc);
		if (ret) {
			CAP_ERR("couldn't get source cnode");
			goto fail1;
		}
		/*
		 * Look up dest
		 *
		 * XXX: It may be possible to get a deadlock here:
		 *
		 *   Thread 1: lcd_cap_grant(cspace1, cptr1, cspace2, cptr2)
		 *
		 *   Thread 2: lcd_cap_grant(cspace2, cptr2, cspace1, cptr1)
		 *
		 * But perhaps not ... Since grant happens during send/recv,
		 * this would mean thread1 would have to be a sender and 
		 * receiver at the same time, which shouldn't be allowed.
		 */
		ret = __cap_cnode_get(cspacedst, c_dst, true, &cnodedst);
		if (ret) {
			CAP_ERR("couldn't get dest cnode");
			goto fail2;
		}
		/*
		 * Make sure source is neither invalid, free, or a cnode, and
		 * dest is free.
		 */
		if (cnodesrc->type == CAP_TYPE_FREE ||
		    cnodesrc->type == CAP_TYPE_INVALID ||
		    cnodesrc->type == CAP_TYPE_CNODE) {
			CAP_ERR("bad source cnode, type = %d", cnodesrc->type);
			ret = -EINVAL;
			goto fail3;
		}
		if (cnodedst->type != CAP_TYPE_FREE) {
			CAP_ERR("bad dest cnode, type = %d", cnodedst->type);
			ret = -EINVAL;
			goto fail3;
		}
		/*
		 * Try to grant
		 */
		done = try_grant(cspacedst, cnodesrc, cnodedst);

		/*
		 * Release both cnodes
		 */
		cap_cnode_put(cnodedst);
		cap_cnode_put(cnodesrc);

		if (!done) {
			/*
			 * Someone is trying to use the cdt; wait 1 ms for
			 * him to finish.
			 */
			msleep(1);
		}

	} while (!done);

	return 0;

 fail3:
	cap_cnode_put(cnodedst);
 fail2:
	cap_cnode_put(cnodesrc);
 fail1:
	return ret;
}

static int try_revoke(struct cspace *cspace, struct cnode *cnode)
{
	struct cnode *child;
	struct cdt_root_node *cdt_root;
	int ret;
	/*
	 * Try to lock the cdt containing cnode
	 */
	if (!cap_mutex_trylock(&cnode->cdt_root->lock)) {
		/*
		 * Tell caller to retry
		 */
		return 0;
	}

	cdt_root = cnode->cdt_root;

	/*
	 * Do a depth-first revoke on cnode's ancestors. If e.g. a child
	 * has any children, they will be shifted into cnode's children via
	 * do_delete_from_cdt. This is why we're using a loop to iterate
	 * over cnode's children, since the list is changing in a peculiar
	 * way.
	 *
	 * XXX: We need to ensure that for all objects - endpoints, pages,
	 * lcd's - it is ok to have the cdt, cnode, and child cnode locked
	 * while we update the microkernel state (e.g., unmap a page since
	 * the rights to it are being revoked). We know there is at least
	 * one reference (cnode) to the object, so it won't be deleted.
	 *
	 * endpoints - should be ok: since we only need to remove the lcd
	 * from the queues if necessary, and this won't require locking
	 * any cspaces, cnodes, cdts.
	 *
	 * pages - should be ok: revocation could mean unmapping the page
	 * in the lcd who owns child, but this won't require locking any
	 * cspace, cnodes, cdts.
	 *
	 * lcd's - should be ok: since all *current* operations on lcd's
	 * are short lived and aren't reasonable to try to cancel, there's no 
	 * microkernel state that needs to be updated.
	 */
	while (!list_empty(&cnode->children)) {
		child = list_first_entry(&cnode->children, struct cnode,
					 siblings);
		/*
		 * Lock child. (If someone has the lock but it is trying to
		 * lock the cdt, they will relinquish.)
		 */
		ret = cap_mutex_lock_interruptible(&child->lock);
		if (ret) {
			CAP_ERR("interrupted");
			goto fail1;
		}
		/*
		 * If the child is in the cdt, its type should match cnode's
		 * type (it shouldn't be invalid, free, or a cnode).
		 */
		BUG_ON(child->type != cnode->type);
		/*
		 * Delete from cdt. 
		 */
		do_delete_from_cdt(child, cdt_root);
		/*
		 * Update microkernel state to reflect rights change 
		 */
		cap_notify_revocation(child->cspace, cnode);
		/*
		 * Mark cnode as free, null out fields.
		 */
		child->type = CAP_TYPE_FREE;
		child->object = NULL;
		child->cdt_root = NULL;
		child->metadata = NULL;
		/*
		 * Unlock child
		 */
		cap_mutex_unlock(&child->lock);
	}

	/*
	 * Unlock cdt
	 */
	cap_mutex_unlock(&cnode->cdt_root->lock);
	/*
	 * Signal we are done
	 */
	return 1;
 fail1:
	return ret;
}

int cap_revoke(struct cspace *cspace, cptr_t c)
{
	struct cnode *cnode;
	int ret;

	/*
	 * Fail for null
	 */
	if (cptr_is_null(c)) {
		CAP_ERR("trying to delete null cptr");
		return -EINVAL;
	}

	/*
	 * This whole thing needs to go in a loop - we need to release the
	 * cnode and keep trying until we can lock the cdt that contains it.
	 */
	do {
		/*
		 * Try to get parent cnode
		 */
		ret = cap_cnode_get(cspace, c, &cnode);
		if (ret) {
			CAP_ERR("couldn't get parent cnode");
			goto fail1;
		}
		/*
		 * Check if cnode is neither invalid, free, nor a cnode (must
		 * contain a capability to a microkernel object)
		 */
		if (cnode->type == CAP_TYPE_FREE ||
		    cnode->type == CAP_TYPE_INVALID ||
		    cnode->type == CAP_TYPE_CNODE) {
			CAP_ERR("cannot revoke on cnode type %d", cnode->type);
			ret = -EINVAL;
			goto fail2;
		}
		/*
		 * Try to do full recursive revoke
		 */
		ret = try_revoke(cspace, cnode);
		/*
		 * Release cnode
		 */
		cap_cnode_put(cnode);

		if (!ret) {
			/*
			 * Someone is using the cdt containing cnode; wait
			 * 1 ms for him to finish, and try again.
			 */
			msleep(1);
		}

	} while (!ret);

	return (ret < 0 ? ret : 0);

 fail2:
	cap_cnode_put(cnode);
 fail1:
	return ret;
}

static void cnode_tear_down(struct cnode *cnode, struct cspace *cspace)
{
	int ret;
	int done;

	do {
		/*
		 * Lock cnode
		 */
		ret = cap_mutex_lock_interruptible(&cnode->lock);
		if (ret) {
			CAP_ERR("interrupted, skipping this cnode");
			goto out1;
		}
		/*
		 * If the cnode is already marked as free, just return.
		 */
		if (cnode->type == CAP_TYPE_FREE)
			goto out2;
		/*
		 * Delete the cnode
		 */
		done = try_delete_cnode(cspace, cnode);

		/*
		 * Release cnode
		 */
		cap_mutex_unlock(&cnode->lock);

		if (!done) {
			/*
			 * Someone else is using the cdt; wait 1 ms for him
			 * to finish.
			 */
			msleep(1);
		}

	} while (!done);

	return;

 out2:
	cap_mutex_unlock(&cnode->lock);
 out1:
	return;
}

static void cnode_table_tear_down(struct cnode_table *t, struct cspace *cspace)
{
	int i;
	struct cnode *cnode;

	/*
	 * Loop over cap slots (first half), and tear down each cnode
	 */
	for (i = 0; i < (CAP_CSPACE_CNODE_TABLE_SIZE >> 1); i++) {
		cnode = &t->cnode[i];
		cnode_tear_down(cnode, cspace);
	}

	return;
}

static void cspace_tear_down(struct cspace *cspace)
{
	struct list_head *cursor, *next;
	struct cnode_table *t;

	/*
	 * We marked the cspace as being deleted, so no one can change
	 * the radix tree (e.g., add new cnode tables). So it's safe to
	 * iterate over them. If we are able to free all contained cnodes,
	 * then it is also ok to free the cnode_table and remove it from
	 * the list.
	 *
	 * We iterate over each one and look at the cap slots (the cnode
	 * slots are either free or point to other tables).
	 */

	list_for_each_safe(cursor, next, &cspace->table_list) {
		t = list_entry(cursor, struct cnode_table, table_list);
		/*
		 * Tear down the table
		 */
		cnode_table_tear_down(t, cspace);
		/*
		 * Delete it from list and free it
		 */
		list_del(&t->table_list);
		cap_cache_free(cspace->cnode_table_cache, t);
	}

	/*
	 * Get rid of the table cache
	 */
	cap_cache_destroy(cspace->cnode_table_cache);

	return;
}

void cap_destroy_cspace(struct cspace *cspace)
{
	int ret;
	/*
	 * Lock the cspace, and mark it as being deleted. This will prevent
	 * any insert's, delete's, revoke's, etc. from trying to traverse
	 * the cnode table tree.
	 */
	ret = cap_mutex_lock_interruptible(&cspace->lock);
	if (ret) {
		CAP_ERR("interrupted");
		goto fail1;
	}
	/*
	 * Confirm cspace is valid (this check is probably not necessary
	 * since we can't race on cspace tear down, but maybe it will be
	 * in the future ...)
	 */
	if (cspace->state != ALLOCATION_VALID) {
		CAP_ERR("cspace already freed?");
		goto fail2;
	}
	/*
	 * Mark it as being deleted
	 */
	cspace->state = ALLOCATION_MARKED_FOR_DELETE;
	/*
	 * Unlock cspace
	 */
	cap_mutex_unlock(&cspace->lock);
	/*
	 * Start tearing it down
	 */
	cspace_tear_down(cspace);

	return;

 fail2:
	cap_mutex_unlock(&cspace->lock);
 fail1:
	return;
}
