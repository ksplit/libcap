# libcap

libcap is a capability management library. The main purpose is to provide a 
capability library which can be used across
different systems. This library will provide functionalities including creating
cspace, adding capabilities to cspace, revoking capabilities from cspace etc.

## External API

The full API is described in [libcap.h](include/libcap.h).

## Assumptions

We assume that for any CDT, an object will only be added to the tree
once, and will never derive from its children (i.e. no loops). A `cap_insert` and
a `cap_grant` should always be a safe operation, only 
`cap_derive`s can be invalid.

For example, You can do:

```C
cap_insert(<cspace a>, <cptr a>, <obj a>);
cap_insert(<cspace a>, <cptr b>, <obj b>);
cap_derive(<cspace a>, <cptr a>, <cspace a>, <cptr b>).
```

But you cannot do:

```C
cap_insert(<cspace a>, <cptr a>, <obj a>);
cap_insert(<cspace a>, <cptr b>, <obj b>);
cap_derive(<cspace a>, <cptr a>, <cspace a>, <cptr b>).
// Bad! Can't have loops!
cap_derive(<cspace a>, <cptr b>, <cspace a>, <cptr a>);
```

And you cannot do:

```C
cap_insert(<cspace a>, <cptr a>, <obj a>);
cap_insert(<cspace a>, <cptr b>, <obj b>);
cap_derive(<cspace a>, <cptr a>, <cspace a>, <cptr b>).
cap_insert(<cspace a>, <cptr c>, <obj b>
// Bad! Double insert in the same CDT!
cap_derive(<cspace a>, <cptr a>, <cspace a>, <cptr c>)
```
