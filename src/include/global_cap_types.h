
/* GLOBAL CAPABILITY TYPES ADDENDUM ---------------------------------------- */

/* 
 * (Added to libcap.h by configure.)
 *
 * This extends the interface if the build configuration allows for a 
 * global capability type system. See the --enable-global-cap-types 
 * configure feature. These are for backward compatability with the 
 * global type system.
 */

/**
 * cap_init_cspace -- Similar to cap_init_cspace_with_type, but defaults
 *                    to use the global type system
 * @cspace: the cspace to initialize
 */
int cap_init_cspace(struct cspace *cspace);
/**
 * cap_register_type -- Similar to cap_register_private_type, but adds type
 *                      to the default global type system
 * @type: integer type index / identifier
 * @ops: the cap_type_ops to associate with this type
 */
cap_type_t cap_register_type(cap_type_t type, const struct cap_type_ops *ops);

