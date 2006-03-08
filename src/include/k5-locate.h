#ifndef K5_PLUGIN_H_INCLUDED
#define K5_PLUGIN_H_INCLUDED
#include "krb5.h"

enum locate_service_type {
    locate_service_kdc = 1,
    locate_service_master_kdc,
    locate_service_kadmin,
    locate_service_krb524,
    locate_service_kpasswd
};

struct krb5plugin_service_locate_ftable {
    int vmajor, vminor;
    /* Per-context setup and teardown.  Returned void* blob is
       private to the plugin.  */
    krb5_error_code (*init)(krb5_context, void **);
    void (*fini)(void *);
    /* Callback function returns non-zero if the plugin function
       should quit and return; this may be because of an error, or may
       indicate we've already contacted the service, whatever.  The
       lookup function should only return an error if it detects a
       problem, not if the callback function tells it to quit.  */
    krb5_error_code (*lookup)(void *,
			      enum locate_service_type svc, const char *realm,
			      int socktype, int family,
			      int (*cbfunc)(void *,int,struct sockaddr *),
			      void *cbdata);
};
#endif
