/**
 * cap.c - cspaces, cdt's, and operations
 *
 * Copyright: University of Utah
 */
#include <libcap.h>
#include <libcap_internal.h>

struct cdt_cache {
	cap_mutex_t lock;
	cap_cache_t *cdt_root_cache;
};

static struct cdt_cache cdt_cache;
static cap_mutex_t global_lock;

#ifdef CAP_ENABLE_GLOBAL_TYPES
/*
 * The internal global type system
 */
static struct cap_type_system global_ts;
#endif 

/*
 * This is used in a hack to make the cnode table slab caches
 * work. See init cspace routine.
 */
static unsigned long long cspace_id = 0;

int cap_init(void)
{
	int ret;
	/*
	 * Initialize cptr cache subsystem
	 */
	ret = __cptr_init();
	if (ret) {
		CAP_ERR("failed to initialize cptr cache subsystem");
		goto fail1;
	}
	/*
	 * Initialize cdt cache
	 */
	cdt_cache.cdt_root_cache = cap_cache_create(cdt_root_node);
	if (!cdt_cache.cdt_root_cache) {
		CAP_ERR("failed to initialize cdt_root_node allocator");
		ret = -ENOMEM;
		goto fail2;
	}
	/*
	 * Initialize locks
	 */
	cap_mutex_init(&cdt_cache.lock);
	cap_mutex_init(&global_lock);
#ifdef CAP_ENABLE_GLOBAL_TYPES
	/*
	 * Initialize global type system
	 */
	ret = cap_type_system_init(&global_ts);
	if (ret) {
		CAP_ERR("global type system init failed");
		goto fail3;
	}
#endif
	
	return 0;

#ifdef CAP_ENABLE_GLOBAL_TYPES
fail3:
	cap_cache_destroy(cdt_cache.cdt_root_cache);
#endif
fail2:
	__cptr_fini();
fail1:
	return ret;
}

void cap_fini(void)
{
	/*
	 * Destroy cdt cache
	 */
	cap_cache_destroy(cdt_cache.cdt_root_cache);
	/*
	 * Tear down cptr cache subsystem
	 */
	__cptr_fini();
#ifdef CAP_ENABLE_GLOBAL_TYPES
	/*
	 * Destroy global type system
	 */
	cap_type_system_destroy(&global_ts);
#endif
}

#ifdef CAP_ENABLE_GLOBAL_TYPES
cap_type_t cap_register_type(cap_type_t type, const struct cap_type_ops *ops)
{
	return cap_register_private_type(&global_ts, type, ops);
}
#endif

/**
 * Allocates a new cdt root node using the cdt cache.
 */
static struct cdt_root_node *__cap_cdt_root_create(void)
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
    cdt_node->refcount = 0;
    cdt_node->parent = NULL;
	cap_mutex_init(&cdt_node->lock);
	cap_mutex_unlock(&cdt_cache.lock);

 out:
	return cdt_node;
}

/** 
 * Free a cdt_root_node previously allocated with `__cap_cdt_root_create`. 
 * This function should only be called by `__cap_cdt_root_decref`. */
static void __cap_cdt_root_free(struct cdt_root_node *cdt_node)
{
	int ret;

	ret = cap_mutex_lock_interruptible(&cdt_cache.lock);
	if (ret) {
		CAP_ERR("interrupted");
        return;
	}

	cdt_node->state = ALLOCATION_REMOVED;
	cap_cache_free(cdt_cache.cdt_root_cache, cdt_node);
	cap_mutex_unlock(&cdt_cache.lock);
}

/* Increment the reference count on the given cdt_root. The cdt_root lock must
 * be held to call this function. */
static inline void __cap_cdt_root_incref(struct cdt_root_node *cdt_root) {
    cdt_root->refcount++;
}

/* Decrement the reference count on the given cdt_root. Since this function
 * assumes that there's someone that wants to keep a lock on the CDT, don't
 * allow decref no_locks that will free the cdt_root. The cdt_root lock must
 * be held when this function is called. */
static inline void __cap_cdt_root_decref_no_unlock(struct cdt_root_node *cdt_root) {
    CAP_BUG_ON(cdt_root->refcount <= 1
               && "Tried to decref_no_unlock a cdt_root at 1 or fewer references.");
    cdt_root->refcount--;
}

/* This function decrements the reference count on the given cdt_root. 
 * This function frees the cdt_root when the count reaches zero. The cdt_root
 * lock must be held when this function is called, it will be released by
 * this function. */
static inline void __cap_cdt_root_decref(struct cdt_root_node *cdt_root) {
    CAP_BUG_ON(cdt_root->refcount <= 0 
               && "Tried to decref a cdt_root at 0 references");
    cdt_root->refcount--;
    /* A thread must have this cdt_root's lock to call decref, but they're
     * specifically signaling the fact that they no longer reference this
     * cdt_root, so unlock the CDT lock for this root. */
    cap_mutex_unlock(&cdt_root->lock);
    if (cdt_root->refcount == 0) {
        __cap_cdt_root_free(cdt_root);
    }
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
int cap_init_cspace_with_type_system(struct cspace *cspace,
				struct cap_type_system *ts)
{
	int ret;
	char name[32];

	ret = cap_mutex_init(&cspace->lock);
	if (ret) {
		CAP_ERR("mutex initialization failed");
		return ret;
	}
	/*
	 * Install type system
	 */
	cspace->ts = ts;
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

#ifdef CAP_ENABLE_GLOBAL_TYPES
int cap_init_cspace(struct cspace *cspace)
{
	return cap_init_cspace_with_type_system(cspace, &global_ts);
}
#endif

inline void cap_cspace_set_owner(struct cspace *cspace, void * owner) {
    cspace->owner = owner;
}
inline void* cap_cspace_owner(struct cspace *cspace) { return cspace->owner; }

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

    /* Save the cptr for the cnode if we successfully looked it up. */
    if (ret >= 0) { (*cnode)->cptr = c; }

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
			"cnode lookup failed with ret = %d\n", ret);
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

/* Get the type ops for the given cnode. If no type ops can be found,
 * an error message is printed and NULL is returned. */
static struct cap_type_ops * __cap_cnode_type_ops(struct cnode *cnode) {
    if (cnode->type < CAP_TYPE_FIRST_NONBUILTIN || cnode->type >= CAP_TYPE_MAX) {
        CAP_ERR("invalid object type %d -- BUG!", cnode->type);
        return NULL;
    }

    struct cap_type_ops * ops = &cnode->cspace->ts->types[cnode->type];

    if (! ops->name) { 
        CAP_ERR("invalid object type %d -- BUG!", cnode->type); 
        return NULL;
    }

    return ops;
}


static int __cap_notify_insert(struct cnode *c, void * callback_payload) {
    struct cap_type_ops *ops = __cap_cnode_type_ops(c);
    if (ops && ops->insert) { return ops->insert(c, callback_payload); }
    return 0;
}

/*
 * Mark cnode as free, null out fields.
 *
 * XXX: We could possibly free up the cnode table if all of its cnodes
 * are free. For now, they just hang around and will be freed when
 * the whole cspace is torn down.
 */
static void __cap_cnode_mark_free(struct cnode * cnode) {
	cnode->type = CAP_TYPE_FREE;
	cnode->object = NULL;
	cnode->cdt_root = NULL;
	cnode->metadata = NULL;
}


int cap_insert(struct cspace *cspace, cptr_t c, void *object, cap_type_t type, 
               void *callback_payload)
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

	/*
	 * Set up cdt
	 */
    cnode->cdt_root = __cap_cdt_root_create();
    if (cnode->cdt_root == NULL) { goto fail; }

    __cap_cdt_root_incref(cnode->cdt_root);

    ret = __cap_notify_insert(cnode, callback_payload);

    if (ret < 0) { goto fail1; }

finish:
	/*
	 * Release cnode
	 */
	cap_cnode_put(cnode);

	return ret;

fail1:
    __cap_cdt_root_decref_no_unlock(cnode->cdt_root);
fail:
    __cap_cnode_mark_free(cnode);
    ret = -1;
    goto finish;
}

static int __cap_notify_delete(struct cnode *cnode, void * callback_payload) {
    struct cap_type_ops * ops = __cap_cnode_type_ops(cnode);
    if (ops && ops->delete) { return ops->delete(cnode, callback_payload); }
    return 0;
}

static int __cap_notify_grant(struct cnode *src, struct cnode *dst, 
                              void * callback_payload) {
    struct cap_type_ops *ops = __cap_cnode_type_ops(src);
    if (ops && ops->grant) { return ops->grant(src, dst, callback_payload); }
    return 0;
}

static int __cap_notify_derive(struct cnode *src, struct cnode *dst, 
                               void * callback_payload) {
    struct cap_type_ops *src_ops = __cap_cnode_type_ops(src);
    if (src_ops && src_ops->derive_src) { 
        int ret = src_ops->derive_src(src, dst, callback_payload);
        if (ret < 0) { return ret; }
    }
    struct cap_type_ops *dst_ops = __cap_cnode_type_ops(src);
    if (dst_ops && dst_ops->derive_dst) { 
        return src_ops->derive_dst(src, dst, callback_payload); 
    }
    return 0;
}

/**
 * Does actual removal from cdt. When this function exits, the CDT will no
 * longer be locked. 
 *
 * ** Expects cnode and cdt_root to be locked, in that order. **
 */
// was called "do_delete_from_cdt"
static inline void __cap_cdt_remove_(struct cnode *cnode) {
	/*
	 * Make the cnode's children the children of cnode's parent by
	 * putting them in the cnode's siblings list. (Note that
	 * list_splice does the right thing when children or siblings is
	 * empty.) Re-initializes cnode->children to be empty, so no need to
     * do a del.
	 */
	list_splice_init(&cnode->children, &cnode->siblings);

	/*
	 * Remove cnode from list of siblings (won't break if siblings is
	 * empty).
	 */
	list_del_init(&cnode->siblings);
}

/* Same as __cap_cdt_remove_, but does a no_unlock decref and doesn't release
 * the CDT lock. */
static void __cap_cdt_remove_no_unlock(struct cnode *cnode) {
    __cap_cdt_remove_(cnode);
    __cap_cdt_root_decref_no_unlock(cnode->cdt_root);
    cnode->cdt_root = NULL;
}

/* Same as __cap_cdt_remove_, but does a real decref and releases the CDT lock. */ 
static void __cap_cdt_remove(struct cnode *cnode) {
    __cap_cdt_remove_(cnode);
    __cap_cdt_root_decref(cnode->cdt_root);
    cnode->cdt_root = NULL;
}

static bool __cap_cnode_is_used(struct cnode * c) {
	return ! (c->type == CAP_TYPE_FREE ||
			  c->type == CAP_TYPE_INVALID ||
			  c->type == CAP_TYPE_CNODE);
}

static bool __cap_cnode_is_free(struct cnode * c) {
	return (c->type == CAP_TYPE_FREE);
}

/* Update the cdt_root of the given cnode (and the refcount of any intermediate
 * cdt_roots) given a know "real" cdt_root (a cdt_root whose parent is null). The
 * "real" root isn't locked, so it's lock can be held while this function is
 * called. This function is not safe to call unless the lock on the given cdt_root
 * is held. Returns 0 on succes, returns a negative value if interrupted. */
static int __cap_cnode_fixup_cdt_root_trusted_root(struct cdt_root_node *real_root,
                                                   struct cnode *c) {
    struct cdt_root_node * old_root = c->cdt_root;
    struct cdt_root_node * root = old_root;
    if (root == real_root) { return 0; }
    while (root != real_root) {
        /* Any code calling this function should already hold the root lock, and
         * any code acquiring an intermediate lock will back off, so it's safe
         * to call this blocking. */
        int status = cap_mutex_lock_interruptible(&root->lock);
        if (status) { return status; }
        old_root = root;
        root = root->parent;
        /* decref our reference to the intermediate root */
        __cap_cdt_root_decref(old_root);
    }
    return 0;
}

/* Acquire the CDT root lock for the CDT associated with this cnode 'c'.
 * This function will update cdt_root pointers and reference count appropriately
 * if the tree this cnode was originally part of is spliced onto another CDT. */
static bool __cap_cnode_try_acquire_cdt_root(struct cnode *c) {
    struct cdt_root_node * old_root = c->cdt_root;
    struct cdt_root_node * root = old_root;
    /* Always have to lock our current root, even if it's not the "real" root. */
    if (cap_mutex_trylock(&root->lock)) { goto fail; /* old_root = root */ }
    while (root->parent != NULL) {
        old_root = root;
        root = root->parent;
        /* Try and lock our new root (the parent of our current) */
        if (cap_mutex_trylock(&root->lock)) { goto fail; }
        /* Update the roots */
        c->cdt_root = root;
        /* don't __cap_cdt_root_incref because the incref happens implicitly on
         * derive */
        __cap_cdt_root_decref(old_root);
    }
    return true;
fail:
    cap_mutex_unlock(&old_root->lock);
    return false;
}

/* Small wrapper, to match `__cap_cnode_acquire_cdt_root` */
static inline void __cap_cnode_release_cdt_root(struct cnode *c) {
    cap_mutex_unlock(&c->cdt_root->lock);
}

/* Returns true if this cnode is a root node of the CDT it's a member of. Note:
 * there may be multiple root nodes in a CDT. Currently, a cnode is considered to
 * be a root only if no cnode in it's 'siblings' list has this cnode in their
 * 'chidlren' list. */
static bool __cap_cnode_is_root(struct cnode *c) {
    struct list_head *sib_cursor;
    list_for_each(sib_cursor, &c->siblings) {
        /* This is ok because to do without locking the cnode, because we
         * have a CDT lock and will only be touching CDT stuff. */
        struct cnode *sibling = list_entry(sib_cursor, struct cnode, children);
        struct list_head *child_cursor;
        list_for_each(child_cursor, &sibling->children) {
            /* We're in this siblings children list, return false */
            if (child_cursor == &c->siblings) { return false; }
        }
    }
    return true;
}

/* Try to actually add 'dst' as a child of 'src' in src's CDT. */
static int __cap_try_derive(struct cnode *src, struct cnode *dst, 
                            __attribute__ ((unused)) void * args_,
                            void * callback_payload) {
    int ret = 0;

    /* Both cnodes should point to valid objects in a derive operation */
    if (! __cap_cnode_is_used(src)) {
        CAP_ERR("bad source cnode, type = %d", src->type);
        ret = -EINVAL;
        goto fail3;
    }

    if (! __cap_cnode_is_used(dst)) {
        CAP_ERR("bad dest cnode, type = %d", dst->type);
        ret = -EINVAL;
        goto fail3;
    }

    /* Check if we're trying to derive from our own cdt_root. This is just
     * to avoid infinite looping for locks. We will fail the 
     * __cap_cnode_try_acquire_cdt_root if both nodes share a cdt_root (because
     * we'll try and lock twice. */
    if (src->cdt_root == dst->cdt_root) {
        ret = -EINVAL;
        CAP_ERR("tried to derive from our own root");
        goto fail;
    }

    if (!__cap_cnode_try_acquire_cdt_root(src)) { 
        CAP_ERR("Couldn't lock source CDT");
        goto fail3; 
    }

    if (!__cap_cnode_try_acquire_cdt_root(dst)) { 
        CAP_ERR("Couldn't lock dest CDT");
        goto fail2;
    }

    if (!__cap_cnode_is_root(dst)) { 
        ret = -EINVAL; 
        CAP_ERR("tried to add non-root node to a new CDT tree (derive)");
        goto fail; 
    }

    /* None of the effects we do below are externally observable from the cnode, 
     * so it's OK to do this here. */
    ret = __cap_notify_derive(src, dst, callback_payload);
    if (ret < 0) {
        goto fail;
    }

	/*
	 * Add dest cnode to source's children in cdt
	 */
    list_move(&dst->siblings, &src->children);

    /* Note that cdt_root is now a sub-root for our children and siblings. */
    dst->cdt_root->parent = src->cdt_root;

    /* All of our current cdt_root's children are now dependent on the new 
     * cdt_root */
    src->cdt_root->refcount += dst->cdt_root->refcount;

    /* Decref from our old root, this is why we skip releasing dst's cdt_root */
    __cap_cdt_root_decref(dst->cdt_root);

    /* Make our cdt_root point to the real cdt_root */
    dst->cdt_root = src->cdt_root;

    ret = 1;

fail:
    __cap_cnode_release_cdt_root(dst);
fail2:
    __cap_cnode_release_cdt_root(src);
fail3:
    return ret;
}

static void __cap_try_grant_cnode_copy(struct cnode *src, struct cnode *dst, 
                                       bool do_list) {
    dst->type = src->type;
    dst->object = src->object;
    dst->cdt_root = src->cdt_root;
    if (do_list) { dst->siblings = src->siblings; }
}

static int __cap_try_grant(struct cnode *src, struct cnode *dst, void * args_,
                           void * callback_payload) {
    cap_type_t * o_type = (cap_type_t *) args_;
    int ret;
    if (!__cap_cnode_is_used(src)) {
        CAP_ERR("bad source cnode, type = %d", src->type);
        ret = -EINVAL;
        goto fail;
    }

    if (!__cap_cnode_is_free(dst)) {
        CAP_ERR("bad dest cnode, type = %d", dst->type);
        ret = -EINVAL;
        goto fail;
    }

	/*
	 * Try to lock the cdt containing source cnode (dest cnode should
	 * not be in a cdt)
	 */
    if (!__cap_cnode_try_acquire_cdt_root(src)) { ret = 0; goto fail; }

	/*
	 * Add dest cnode to source's children in cdt
	 */
	list_add(&dst->siblings, &src->children);

    /* save dst contents in case we need to roll-back */
    struct cnode _tmp;
    __cap_try_grant_cnode_copy(dst, &_tmp, true);

    __cap_try_grant_cnode_copy(src, dst, false);

    /* Invoke the grant callback for this cnode type. No additional locking
     * of the ts is needed because all ts updated are additive. */
    ret = __cap_notify_grant(src, dst, callback_payload);

    /* Notify the caller about the type of the granted node */
    *o_type = cap_cnode_type(src);

    if (ret < 0) { /* rollback */
        CAP_ERR("grant callback aborted grant. code = %d, type = %d", ret, src->type);
        /* remove the dst node from the siblings list */
        list_del(&dst->siblings);
        /* Fixup everything else from our temporary copy.
         * XXX: Can't use a memcpy 'cause we need to keep the same 
         * cnode lock. I'm not sure if copying held locks is OK. */
        __cap_try_grant_cnode_copy(&_tmp, dst, true);
    } else {
        /* increment the CDT refcount for the granted-to node. */
        __cap_cdt_root_incref(dst->cdt_root);
        ret = 1;
    }

    __cap_cnode_release_cdt_root(src);

fail:
    return ret;
}

/**
 * Tries to lock cdt and remove cnode from it. Returns non-zero if 
 * cnode successfully deleted.
 */
static int __cap_try_delete(struct cnode *cnode, 
                            __attribute__((unused)) void * _args,
                            void * callback_payload)
{
    if (! __cap_cnode_is_used(cnode)) {
        CAP_ERR("bad cnode, type = %d", cnode->type);
        return -EINVAL;
    }

	/*
	 * Try to lock the cdt
	 */
    if (!__cap_cnode_try_acquire_cdt_root(cnode)) { return 0; }

	/* Order of what follows is important */

	/*
	 * Update microkernel state to reflect rights change (e.g., if we're
	 * deleting a cnode for an endpoint, we need to ensure the lcd isn't
	 * in the endpoint's queues).
	 */
    int ret = __cap_notify_delete(cnode, callback_payload);

    if (ret < 0) { /* abort delete */
        CAP_ERR("delete handler aborted delete, code = %d, type = %d", ret, cnode->type);
        __cap_cnode_release_cdt_root(cnode);
        return ret;
    }

    /* Actually remove from the CDT. The CDT is unlocked and nulled in that
     * function. */
    __cap_cdt_remove(cnode);

    __cap_cnode_mark_free(cnode);

	/*
	 * Signal we are done
	 */
	return 1;
}

struct __cap_try_revoke_args {
    cap_revoke_till_f till_f;
    void * till_f_payload;
};

static int __cap_try_revoke(struct cnode *cnode, void * _args, void * callback_payload)
{
    struct __cap_try_revoke_args * args = (struct __cap_try_revoke_args *) _args;
    if (! __cap_cnode_is_used(cnode)) {
        CAP_ERR("bad cnode, type = %d", cnode->type);
        return -EINVAL;
    }

	struct cnode *child;
	int ret;

	/*
	 * Try to lock the cdt containing cnode
	 */
    if (!__cap_cnode_try_acquire_cdt_root(cnode)) { return 0; }

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

    /* Note: This should do a depth-first traversal of the nodes, skipping any
     * sub-trees that our `till_f` function tells us to skip. */

    struct list_head * prev = &cnode->children;
    struct list_head * cur = prev->next;
    /* The tree lists are circular, so keep traversing the 'children' list
     * until we reach the root again. We have to save the "next" ptr before
     * we actually loop because 'cur' will become invalid if it gets removed
     * from the tree. */
    for (; cur != &cnode->children; cur = prev->next) {
        child = list_entry(cur, struct cnode, siblings);

		/*
		 * Lock child. (If someone has the lock but it is trying to
		 * lock the cdt, they will relinquish.)
		 */
		ret = cap_mutex_lock_interruptible(&child->lock);
		if (ret) {
			CAP_ERR("interrupted on cnode");
			goto fail1;
		}
		/*
		 * If the child is in the cdt, it shouldn't be invalid, 
         * free, or a cnode.
		 */
		CAP_BUG_ON(!__cap_cnode_is_used(child));

		if (args->till_f(child, args->till_f_payload)) {
            CAP_MSG("Skipping revoke on %#0lx because of till_f\n", 
                    cptr_val(cap_cnode_cptr(child)));
            /* This node is guarnteed to be in the output tree, so save it
             * as the new "prev" */
            prev = cur;

			goto next_child;
		}

        /* We need to update the cdt_root of this child before we call
         * cap_cdt_remove_no_unlock because we never called
         * __cap_cnode_try_acquire_cdt_root. We also have to call fixup to
         * make sure intermediate root node's reference counts are updated
         * properly. */
        ret = __cap_cnode_fixup_cdt_root_trusted_root(cnode->cdt_root, child);
        if (ret) {
			CAP_ERR("interrupted on fixup");
			goto fail1;
        }

		/*
		 * Delete from cdt. Don't drop the CDT lock.
		 */
        __cap_cdt_remove_no_unlock(child);

        /* If we remove a node, it may have spliced its children in before our
         * next. So, re-start the traversal from the "next" of the previous node.
         * This case is handled implicitly via the post condition of the for loop. */

		/*
		 * Update microkernel state to reflect rights change 
		 */
        __cap_notify_delete(child, callback_payload);

        __cap_cnode_mark_free(child);

next_child:

		/*
		 * Unlock child
		 */
		cap_mutex_unlock(&child->lock);
	}

    __cap_cnode_release_cdt_root(cnode);

	/*
	 * Signal we are done
	 */
	ret = 1;
 fail1:
	return ret;
}



/* Do some operation on a pair of cnodes, the `op` function should have the following
 * contract:
 *      - If the operation cannot currently be completed and should be
 *        retried (i.e., couldn't acquire CDT) return 0.
 *      - If the operation completes successfully, return 1.
 *      - If the operation fails irrecoverably, return a negative value that
 *        will then be returned from this function.
 * If the operation completes successfully, 1 is returned. 'op_name' is used
 * in error messages. */
int __cap_cnode_binop(struct cspace *cspace_src, cptr_t c_src,
                      struct cspace *cspace_dst, cptr_t c_dst,
                      bool alloc_dest,
                      void *extra,
                      void *callback_payload,
                      char * op_name,
                      int (*op)(struct cnode *src, struct cnode *dst, 
                                void *extra, void * callback_payload)) {
    struct cnode *src, *dst;
    int ret;

	/*
	 * Fail for null
	 */
	if (cptr_is_null(c_src) || cptr_is_null(c_dst)) {
		CAP_ERR("trying to \"%s\" with a null cptr", op_name);
		return -EINVAL;
	}

	/*
	 * Fail if source and dest cspaces have different
	 * type systems. (It doesn't make sense to insert an
	 * object of an unregistered type in the dest cspace.)
	 *
	 * XXX: We don't do this under a lock, since, for now,
	 * a cspace's type system cannot change after it is
	 * created.
	 */
	if (cspace_src->ts != cspace_dst->ts) {
		CAP_ERR("source and dest cspaces have different type systems");
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
		ret = __cap_cnode_get(cspace_src, c_src, false, &src);
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
		ret = __cap_cnode_get(cspace_dst, c_dst, alloc_dest, &dst);
		if (ret) {
			CAP_ERR("couldn't get dest cnode\n");
			goto fail2;
		}

		ret = op(src, dst, extra, callback_payload);
        if (ret < 0) { goto fail3; }

		/*
		 * Release both cnodes
		 */
		cap_cnode_put(dst);
		cap_cnode_put(src);

		if (!ret) {
            /* Op wants us to try again later; wait 1 ms. */
			msleep(1);
		}
	} while (!ret);

	return 0;

 fail3:
	cap_cnode_put(dst);
 fail2:
	cap_cnode_put(src);
 fail1:
	return ret;
}

/* perform a unary operation over a cptr in the given cspace. The given
 * function 'op' will be called with the cnode that is pointed to by the given
 * cptr. The protocol for this function is described in the comment
 * above __cap_cnode_binop. 'op_name' is used for error messages. */
int __cap_cnode_unop(struct cspace *cspace, cptr_t c,
                     bool alloc,
                     void * extra,
                     void * callback_payload,
                     char * op_name,
                     int (*op)(struct cnode *, void * extra, void * payload)) {
	struct cnode *cnode;
	int ret;

	/*
	 * Fail for null
	 */
	if (cptr_is_null(c)) {
		CAP_ERR("trying to %s null cptr", op_name);
		return -EINVAL;
	}

	/*
	 * This whole thing needs to go in a loop - we need to release the
	 * cnode and keep trying until we can lock the cdt that contains it.
	 */
	do {
		ret = __cap_cnode_get(cspace, c, alloc, &cnode);
		if (ret) {
			CAP_ERR("couldn't get cnode");
			goto fail1;
		}

        CAP_MSG("Extra on real cap msg: %p\n", extra);
        /* Do the op, if we get a fail code, exit the loop. */
        ret = op(cnode, extra, callback_payload);
        if (ret < 0) { goto fail2; }

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

    return 0;

 fail2:
	cap_cnode_put(cnode);
 fail1:
	return ret;
}

int cap_derive(struct cspace *cspacesrc, cptr_t c_src,
               struct cspace *cspacedst, cptr_t c_dst,
               void * callback_payload) {
    return __cap_cnode_binop(cspacesrc, c_src, cspacedst, c_dst, false,
                             NULL, callback_payload,
                             "cap_derive", __cap_try_derive);
}

int cap_derive_cnode(struct cnode * ca, struct cnode *cb,
                     void * callback_payload) {
    int ret = 0;
    while (! ret) {
        ret = __cap_try_derive(ca, cb, NULL, callback_payload);
        if (ret < 0) { return ret; }
    }
    return 0;
}

int cap_grant(struct cspace *cspacesrc, cptr_t c_src,
			  struct cspace *cspacedst, cptr_t c_dst,
              void * callback_payload,
              cap_type_t * type) {
    return __cap_cnode_binop(cspacesrc, c_src, cspacedst, c_dst, true,
                             (void *) type, callback_payload,
                             "cap_grant", __cap_try_grant);
}

struct __cap_grant_unop_adapter_extra {
    void * orig_extra;
    struct cnode * src_cnode;
};

/* adapter that pulls the src_cnode out of the "extra" arguments from the
 * cap_grant_cnode callback. */
static int __cap_grant_unop_adapter(struct cnode * dst_cnode, void * _extra, void * payload) {
    struct __cap_grant_unop_adapter_extra * extra = 
        (struct __cap_grant_unop_adapter_extra *) _extra;
    return __cap_try_grant(extra->src_cnode, dst_cnode, extra->orig_extra, payload);
}

/* This should be an OK implementation since we've already locked the source
 * cnode and the dest cnode should be unused. */
int cap_grant_cnode(struct cnode * ca,
                    struct cspace * cspacedst, cptr_t c_dst,
                    void * callback_payload,
                    cap_type_t *type) {
    struct __cap_grant_unop_adapter_extra extra = {
        .orig_extra = (void *) type,
        .src_cnode = ca
    };
    return __cap_cnode_unop(cspacedst, c_dst, 
                            true, (void *) &extra, callback_payload, 
                            "cap_grant_cnode",
                            __cap_grant_unop_adapter);
}

void cap_delete(struct cspace *cspace, cptr_t c, void * callback_payload) {
    __cap_cnode_unop(cspace, c, false, NULL, callback_payload, "cap_delete", __cap_try_delete);
}

void cap_delete_cnode(struct cnode * cnode, void * callback_payload) {
    int ret = 0;
    while (! ret) {
        ret = __cap_try_delete(cnode, NULL, callback_payload);
        if (ret < 0) { return; }
    }
}

static bool __always_false(__attribute__((unused)) struct cnode *cnode,
                           __attribute__((unused)) void * payload) {
	return false;
}

int cap_revoke(struct cspace *cspace, cptr_t c, void * callback_payload) {
    CAP_MSG("Doing real cap revoke\n");
    struct __cap_try_revoke_args revoke_args = {
        .till_f = __always_false,
        .till_f_payload = NULL,
    };
	return __cap_cnode_unop(cspace, c, false,
                            (void *) &revoke_args, callback_payload,
                            "cap_revoke", __cap_try_revoke);
}

int cap_revoke_cnode(struct cnode * cnode, void * callback_payload) {
    struct __cap_try_revoke_args revoke_args = {
        .till_f = __always_false,
        .till_f_payload = NULL,
    };

    int ret = 0;
    while (! ret) {
        ret = __cap_try_revoke(cnode, (void *) &revoke_args, callback_payload);
        if (ret < 0) { return ret; }
    }
    return 0;
}


int cap_revoke_till(struct cspace *cspace, cptr_t c, cap_revoke_till_f func, 
                    void * callback_payload, void * till_f_payload) {
    struct __cap_try_revoke_args revoke_args = {
        .till_f = func,
        .till_f_payload = till_f_payload
    };
	return __cap_cnode_unop(cspace, c, false,
                            (void *) &revoke_args, callback_payload,
                            "cap_revoke_till", __cap_try_revoke);
}

int cap_revoke_till_cnode(struct cnode * cnode, cap_revoke_till_f func, 
                          void * callback_payload, void * till_f_payload) {
    int ret = 0;
    struct __cap_try_revoke_args revoke_args = {
        .till_f = func,
        .till_f_payload = till_f_payload
    };
    while (! ret) {
        ret = __cap_try_revoke(cnode, (void *) &revoke_args, callback_payload);
        if (ret < 0) { return ret; }
    }
    return 0;
}

static void cap_cnode_dump_cdt_child(struct cnode * cnode, int depth) {
    char * space = cap_zalloc(1, (depth * 2) + 1);
    if (space == NULL) {
        CAP_ERR("Couldn't dump cdt, failed to alloc memory");
        return;
    }
    memset(space, ' ', (depth * 2));
    space[(depth * 2)] = '\0';
    CAP_MSG("%s(cptr (cspace %p) %#0lx)\n", space, cap_cnode_cspace((cnode)), cap_cnode_cptr((cnode)));
    cap_free(space);

	struct cnode *child;
    struct list_head * cur;

    /* The tree lists are circular, so keep traversing the 'children' list
     * until we reach the root again. */
    list_for_each(cur, &cnode->children) {
        child = list_entry(cur, struct cnode, siblings);

        /* We need to update the cdt_root of this child before we call
         * cap_cdt_remove_no_unlock because we never called
         * __cap_cnode_try_acquire_cdt_root. We also have to call fixup to
         * make sure intermediate root node's reference counts are updated
         * properly. */
        int ret = __cap_cnode_fixup_cdt_root_trusted_root(cnode->cdt_root, child);
        CAP_BUG_ON(ret && "interrupted on fixup");

        cap_cnode_dump_cdt_child(child, depth + 1);
	}
}

void cap_cnode_dump_cdt_unsafe(struct cnode * cnode) {

    while (true) { 
        int res = __cap_cnode_try_acquire_cdt_root(cnode);
        if (res) { break; }
    }

    cap_cnode_dump_cdt_child(cnode, 0);

    __cap_cnode_release_cdt_root(cnode);
}

static void __cap_cnode_tear_down(struct cnode *cnode, struct cspace *cspace)
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

        done = __cap_try_delete(cnode, NULL, NULL);
        if (done < 0) {
            CAP_ERR("try_delete_cnode failed! code=%d", done);
            goto out2;
        }

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
		__cap_cnode_tear_down(cnode, cspace);
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
	/*
	 * Note: We don't destroy the type system at this point. The
	 * libcap user is responsible for destroying that at the
	 * right time.
	 */
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

/* EXPORTS -------------------------------------------------- */

/* These are required for kernel land, so that if we install libcap
 * as a kernel module, other kernel code can link with it. */
EXPORT_SYMBOL(cap_init);
EXPORT_SYMBOL(cap_fini);
EXPORT_SYMBOL(cap_init_cspace_with_type_system);
EXPORT_SYMBOL(cap_register_private_type);
EXPORT_SYMBOL(cap_alloc_cspace);
EXPORT_SYMBOL(cap_free_cspace);
EXPORT_SYMBOL(cap_destroy_cspace);
EXPORT_SYMBOL(cap_cspace_set_owner);
EXPORT_SYMBOL(cap_cspace_owner);
EXPORT_SYMBOL(cap_cnode_get);
EXPORT_SYMBOL(cap_cnode_put);
EXPORT_SYMBOL(cap_cnode_object);
EXPORT_SYMBOL(cap_cnode_type);
EXPORT_SYMBOL(cap_cnode_cspace);
EXPORT_SYMBOL(cap_cnode_metadata);
EXPORT_SYMBOL(cap_cnode_set_metadata);
EXPORT_SYMBOL(cap_cnode_verify);
EXPORT_SYMBOL(cap_cnode_cptr);
EXPORT_SYMBOL(cap_insert);
EXPORT_SYMBOL(cap_delete);
EXPORT_SYMBOL(cap_grant);
EXPORT_SYMBOL(cap_revoke);
EXPORT_SYMBOL(cap_revoke_till);
#ifdef CAP_ENABLE_GLOBAL_TYPES
EXPORT_SYMBOL(cap_init_cspace);
EXPORT_SYMBOL(cap_register_type);
#endif
