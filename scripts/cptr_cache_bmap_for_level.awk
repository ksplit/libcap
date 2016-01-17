#
# Generate the switch statement in the body of
# cap_cptr_cache_bmap_for_level.
#
# Invocation example:
#
#     awk -v cap_cspace_depth_bits=2 -f cptr_cache_bmap_for_level.awk
#
BEGIN {
    
    out = "\tswitch (lvl) {\n";

    for (i = 0; i < (2 ** cap_cspace_depth_bits); i++) {

        out = out "\t\tcase " i ":\n";
        out = out "\t\t\treturn c->bmap" i ";\n";

    }

    out = out "\t\tdefault:\n";
    out = out "\t\t\tCAP_BUG();\n";
    out = out "\t}";

    print out;
}
