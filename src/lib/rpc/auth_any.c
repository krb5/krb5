/*
 * auth_any.c
 * Provides default functions for authentication flavors that do not
 * use all the fields in structauth_ops.
 */

#include <stdio.h>
#include <gssrpc/types.h>
#include <gssrpc/xdr.h>
#include <gssrpc/auth.h>

int authany_wrap(auth, xdrs, xfunc, xwhere)
   AUTH *auth;
   XDR *xdrs;
   xdrproc_t xfunc;
   caddr_t xwhere;
{
     return (*xfunc)(xdrs, xwhere);
}
