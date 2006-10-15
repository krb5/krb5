#include <sys/types.h>
#include <krb5.h>
#include <gssrpc/rpc.h>
#include <kdb.h>
#include "policy_db.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

static 
bool_t xdr_nullstring(XDR *xdrs, char **objp)
{
     u_int size;
                                                                                                                            
     if (xdrs->x_op == XDR_ENCODE) {
          if (*objp == NULL)
               size = 0;
          else
               size = strlen(*objp) + 1;
     }
     if (! xdr_u_int(xdrs, &size)) {
          return FALSE;
        }
     switch (xdrs->x_op) {
     case XDR_DECODE:
          if (size == 0) {
               *objp = NULL;
               return TRUE;
          } else if (*objp == NULL) {
               *objp = (char *) mem_alloc(size);
               if (*objp == NULL) {
                    errno = ENOMEM;
                    return FALSE;
               }
          }
          return (xdr_opaque(xdrs, *objp, size));
                                                                                                                            
     case XDR_ENCODE:
          if (size != 0)
               return (xdr_opaque(xdrs, *objp, size));
          return TRUE;
                                                                                                                            
     case XDR_FREE:
          if (*objp != NULL)
               mem_free(*objp, size);
          *objp = NULL;
          return TRUE;
     }
                                                                                                                            
     return FALSE;
}
                                                                                                                            


bool_t
xdr_osa_policy_ent_rec(XDR *xdrs, osa_policy_ent_t objp)
{
    switch (xdrs->x_op) {
    case XDR_ENCODE:
	 objp->version = OSA_ADB_POLICY_VERSION_1;
	 /* fall through */
    case XDR_FREE:
	 if (!xdr_int(xdrs, &objp->version))
	      return FALSE;
	 break;
    case XDR_DECODE:
	 if (!xdr_int(xdrs, &objp->version))
	      return FALSE;
	 if (objp->version != OSA_ADB_POLICY_VERSION_1)
	      return FALSE;
	 break;
    }
    
    if(!xdr_nullstring(xdrs, &objp->name))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_min_life))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_max_life))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_min_length))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_min_classes))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->pw_history_num))
	return (FALSE);
    if (!xdr_u_int32(xdrs, &objp->policy_refcnt))
	return (FALSE);
    return (TRUE);
}
