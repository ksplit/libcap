/**
 * type_system.c -- capability type systems
 * 
 * Copyright: University of Utah
 */
#include <libcap.h>
#include <libcap_internal.h>

int cap_type_system_alloc(struct cap_type_system **ts)
{

}

int cap_type_system_init(struct cap_type_system *ts)
{

}

void cap_type_system_destroy(struct cap_type_system *ts)
{

}

void cap_type_system_free(struct cap_type_system *ts)
{

}

cap_type_t cap_register_private_type(struct cap_type_system *ts, 
			cap_type_t type, const struct cap_type_ops *ops)
{

}

/* EXPORTS -------------------------------------------------- */

EXPORT_SYMBOL(cap_type_system_alloc);
EXPORT_SYMBOL(cap_type_system_init);
EXPORT_SYMBOL(cap_type_system_destroy);
EXPORT_SYMBOL(cap_type_system_free);
EXPORT_SYMBOL(cap_register_private_type);
