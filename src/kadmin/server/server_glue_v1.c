#define USE_KADM5_API_VERSION 1
#include <kadm5/admin.h>
#include "misc.h"

/*
 * In server_stubs.c, kadmind has to be able to call kadm5 functions
 * with the arguments appropriate for any api version.  Because of the
 * prototypes in admin.h, however, the compiler will only allow one
 * set of arguments to be passed.  This file exports the old api
 * definitions with a different name, so they can be called from
 * server_stubs.c, and just passes on the call to the real api
 * function; it uses the old api version, however, so it can actually
 * call the real api functions whereas server_stubs.c cannot.
 *
 * This is most useful for functions like kadm5_get_principal that
 * take a different number of arguments based on API version.  For
 * kadm5_get_policy, the same thing could be accomplished with
 * typecasts instead.
 */

kadm5_ret_t kadm5_get_principal_v1(void *server_handle,
				  krb5_principal principal, 
				  kadm5_principal_ent_t_v1 *ent)
{
     return kadm5_get_principal(server_handle, principal, ent);
}

kadm5_ret_t kadm5_get_policy_v1(void *server_handle, kadm5_policy_t name,
				kadm5_policy_ent_t *ent)
{
     return kadm5_get_policy(server_handle, name, ent);
}
