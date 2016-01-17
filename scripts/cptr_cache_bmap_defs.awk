#
# Generate the bitmap defs for the cptr_cache type.
#
# Invocation example:
#
#     awk -v cap_cspace_depth_bits=2 -v cap_cspace_cnode_table_bits=6 \
#            -f cptr_cache_bmap_defs.awk
#
BEGIN {
    
    out = "";
    depth = 2 ** cap_cspace_depth_bits;
    slots_per_table = 2 ** cap_cspace_cnode_table_bits;

    for (i = 0; i < depth; i++) {

        # Only half of the slots store capabilities in a cnode table. The
        # other half store pointers to nodes further down in the radix
        # tree.
        slots_in_lvl = (slots_per_table / 2) ** (i + 1);

        out = out "\tunsigned long bmap" i "[CAP_BITS_TO_LONGS(" \
            slots_in_lvl ")];\n";
    }

    print out;
}
