# 
# Calculates total number of slots in a cspace, given the depth and
# cnode table size.
#
# Invocation example:
#
#     awk -v cap_cspace_depth_bits=2 -v cap_cspace_cnode_table_bits=6 \
#             -f cptr_cache_bmap_size.awk
#
BEGIN { 
    depth = 2 ** cap_cspace_depth_bits;
    tsize = 2 ** cap_cspace_cnode_table_bits;
    total = ( (tsize/2) - ((tsize/2)**(depth + 1)) ) / ( 1 - (tsize/2) );
    print total;
}
