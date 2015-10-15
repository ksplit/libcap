#include "../include/types.h"
#include "../include/internal.h"

/*
 * Regular grant.
 * This function is used to grant the capabilities from one cspace to other.
 * Suppose A and B have an ipc channel that connects them. The operating
 * system (user of libcap) could provide the following mechanism for A to
 * grant rights to B.
 * A does an "ipc send" and stores a2 in a special ipc message buffer,
 * and B does a receive and stores b2 in its ipc receive buffer. When the
 * operating system sees that, it would carry out the grant 
 * using libcap library in the following way:
 *
 *  1. Resolve process A to cspace A
 *  2. Resolve process B to cspace B
 *  3. Invoke grant function in the library (libcap).
 *  
 *  This entire functionality has te be tested yet!!
 *  I am testing it and will add the testing results.
 */
int libcap_grant_capability(void *s_cspace, void *d_cspace,
		cptr_t s_cptr, cptr_t d_cptr)
{
	int ret;
	struct cspace *src_cspace = (struct cspace *) s_cspace;
	struct cspace *dest_cspace = (struct cspace *) d_cspace;
	cptr_t src_cptr = s_cptr;
	cptr_t dest_cptr = d_cptr;

	if (cptr_is_null(src_cptr) || cptr_is_null(dest_cptr)) {
		LCD_ERR("trying to grant with a null cptr");
		return -1;
	}


	/* If we know source and destination cspace and corresponding
	 * c_ptr. Then we can simply use the functionality provided
	 * by the LCD framework
	 */
	
	ret = __lcd_cap_grant(src_cspace, src_cptr,  dest_cspace, dest_cptr);

        if (ret) {
                LCD_ERR("failed to transfer cap @ 0x%lx in lcd %p to slot @ 0x%lx in lcd %p",
                        cptr_val(src_cptr), src_cspace, cptr_val(dest_cptr),
                        dest_cspace);
        }

	return ret;
}

/*
 * Setting values of destination cnode based on src cnode.
 * May be needed if such scenario exists.
 * 
 */
int libcap_try_grant_cnode(void *cspacedst, void *cnodesrc,
                void *cnodedst)
{
	/*
	 * Set dest cnode's fields with source's
	 * Removed cdt part from LCD stuff. Assuming cdt is maintained by user.
	 */
	((struct cnode*) cnodedst)->type     = ((struct cnode*) cnodesrc)->type;
	((struct cnode*) cnodedst)->object   = ((struct cnode*) cnodesrc)->object;
	((struct cnode*) cnodedst)->cspace   = (struct cspace*) cspacedst;
	((struct cnode*) cnodedst)->cdt_root = ((struct cnode*) cnodesrc)->cdt_root;

	return 0;
}
