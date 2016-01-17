# 
# Calculates size in bits of an unsigned long. This is pretty trivial
# and could probably be inlined in configure.ac, but for clarity I
# moved it out here.
#
# Invocation example:
#
#     awk -v bytes_in_an_unsigned_long=8 -f ulong_size.awk
#
BEGIN { 
    print bytes_in_an_unsigned_long * 8
}
