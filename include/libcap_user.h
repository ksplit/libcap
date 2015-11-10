#ifndef __LIBCAP_USER_H__
#define __LIBCAP_USER_H__

#include <stdio.h>
#include <pthread.h>

CAP_BUILD_CORE_TYPES_NOBUILTIN();

#define __cap_err(format,...) \
    fprintf(stderr,"CERR: %s:%d: "format,__FUNCTION__,__LINE__,## __VA_ARGS__)
#define __cap_warn(format,...) \
    fprintf(stderr,"CWARN: %s:%d: "format,__FUNCTION__,__LINE__,## __VA_ARGS__)
#define __cap_msg(format,...) \
    fprintf(stderr,"CINFO: %s:%d: "format,__FUNCTION__,__LINE__,## __VA_ARGS__)
#define __cap_debug(format,...) \
    fprintf(stderr,"CDEBUG: %s:%d: "format,__FUNCTION__,__LINE__,## __VA_ARGS__)

#endif /* __LIBCAP_USER_H__ */
