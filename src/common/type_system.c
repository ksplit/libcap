/**
 * type_system.c -- capability type systems
 * 
 * Copyright: University of Utah
 */

#ifdef LCD_DOMAINS
#include <lcd_config/pre_hook.h>
#endif

#include <libcap.h>
#include <libcap_internal.h>

#ifdef LCD_DOMAINS
#include <lcd_config/post_hook.h>
#endif

#define CAP_TYPE_NUM_BUILTIN CAP_TYPE_FIRST_NONBUILTIN

static struct cap_type_ops builtin_cap_types[CAP_TYPE_NUM_BUILTIN] = {
	{"none", NULL, NULL,}, 
	{"invalid", NULL, NULL},
	{"free", NULL, NULL}, 
	{"cnode", NULL, NULL},
};

int 
LIBCAP_FUNC_ATTR
cap_type_system_alloc(struct cap_type_system **ts)
{
	*ts = cap_zalloc(1, sizeof(**ts));
	if (!*ts)
		return -ENOMEM;
	return 0;
}

int 
LIBCAP_FUNC_ATTR
cap_type_system_init(struct cap_type_system *ts)
{
	int i;
	/*
	 * Zero out types
	 *
	 * (This may seem redundant with cap_zalloc in alloc,
	 * but in some cases - like the global_ts in cap.c - we
	 * statically allocate type systems. In some primitive
	 * environments, like LCDs, these variables are not zero'd out.)
	 */
	memset(ts, 0, sizeof(*ts));
	/*
	 * Install built-in types
	 */
	for (i = 0; i < CAP_TYPE_NUM_BUILTIN; i++)
		ts->types[i] = builtin_cap_types[i];
	/*
	 * Init lock
	 */
	cap_mutex_init(&ts->lock);

	return 0;
}

void 
LIBCAP_FUNC_ATTR
cap_type_system_destroy(struct cap_type_system *ts)
{
	int i;
	/*
	 * Free up any strdup'd names in the cap_types array
	 */
	for (i = CAP_TYPE_FIRST_NONBUILTIN; i < CAP_TYPE_MAX; ++i)
		if (ts->types[i].name)
			free(ts->types[i].name);
}

void 
LIBCAP_FUNC_ATTR
cap_type_system_free(struct cap_type_system *ts)
{
	cap_free(ts);
}

cap_type_t 
LIBCAP_FUNC_ATTR
cap_register_private_type(struct cap_type_system *ts, 
			cap_type_t type, const struct cap_type_ops *ops)
{
	int i, ret;

	cap_mutex_lock(&ts->lock);
	if (type <= 0) {
		for (i = CAP_TYPE_FIRST_NONBUILTIN; i < CAP_TYPE_MAX; ++i) {
			if (ts->types[i].name)
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
	} else if (ts->types[i].name) {
		CAP_ERR("cap type %d already in use", type);
		ret = -EADDRINUSE;
		goto out;
	} else {
		ts->types[i].name = strdup(ops->name);
		ts->types[i].delete = ops->delete;
		ts->types[i].revoke = ops->revoke;
		ret = i;
		goto out;
	}
out:
	cap_mutex_unlock(&ts->lock);
	return ret;
}

/* EXPORTS -------------------------------------------------- */

EXPORT_SYMBOL(cap_type_system_alloc);
EXPORT_SYMBOL(cap_type_system_init);
EXPORT_SYMBOL(cap_type_system_destroy);
EXPORT_SYMBOL(cap_type_system_free);
EXPORT_SYMBOL(cap_register_private_type);
