/**
 * type_system.c -- capability type systems
 * 
 * Copyright: University of Utah
 */
#include <libcap.h>
#include <libcap_internal.h>

int cap_type_system_alloc(struct cap_type_system **ts)
{
	*ts = cap_zalloc(1, sizeof(**ts));
	if (!*ts)
		return -ENOMEM;
	return 0;
}

int cap_type_system_init(struct cap_type_system *ts)
{
	/*
	 * Zero out types
	 *
	 * (This may seem redundant with cap_zalloc in alloc,
	 * but in the future, we may allow e.g. statically declared
	 * type systems.)
	 */
	memset(ts, 0, sizeof(*ts));
	/*
	 * Init lock
	 */
	cap_mutex_init(&ts->lock);

	return 0;
}

void cap_type_system_destroy(struct cap_type_system *ts)
{
	/*
	 * Nothing to do for now.
	 */
}

void cap_type_system_free(struct cap_type_system *ts)
{
	cap_free(ts);
}

cap_type_t cap_register_private_type(struct cap_type_system *ts, 
			cap_type_t type, const struct cap_type_ops *ops)
{
	int i, ret;

	cap_mutex_lock(&ts->lock);
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

/* EXPORTS -------------------------------------------------- */

EXPORT_SYMBOL(cap_type_system_alloc);
EXPORT_SYMBOL(cap_type_system_init);
EXPORT_SYMBOL(cap_type_system_destroy);
EXPORT_SYMBOL(cap_type_system_free);
EXPORT_SYMBOL(cap_register_private_type);
