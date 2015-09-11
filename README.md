==library==
libcap

==Description== 
libcap is a capability management library.

==Purpose==
The main purpose is to provide a capability library which can be used across
different systems. This library will provide functionalities including creating
cspace, adding capabilities to cspace, revoking capabilities from cspace etc.

Basic structure can be like this:
signature dummy_func_add_capability(cspace *, capability1 *, capability2 *, ...);
signature dummy_func_revoke_capability(cspace *, capability1 *);

==ToDO==
Further information will be added subsequently.