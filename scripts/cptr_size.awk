# 
# Calculates number of bits needed to store a cptr. Awk is used because
# the CPP cannot do exponentiation, and many systems have awk (no?).
# Moreover, the shell's arithmetic ops (at least non-bash) are limited.
#
# Invocation example:
#
#     awk -v cap_cspace_depth_bits=2 -v cap_cspace_cnode_table_bits=6 \
#             -f cptr_size.awk
#
BEGIN { 
    print ((2 ** cap_cspace_depth_bits) * \
           (cap_cspace_cnode_table_bits - 1) + cap_cspace_depth_bits)
}
