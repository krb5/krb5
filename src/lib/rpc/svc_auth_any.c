/*
 * svc_auth_any.c
 * Provides default service-side functions for authentication flavors
 * that do not use all the fields in struct svc_auth_ops.
 *
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 */

#include <stdio.h>
#include <gssrpc/rpc.h>

static int svc_authany_wrap(SVCAUTH *, XDR *, xdrproc_t, caddr_t);

struct svc_auth_ops svc_auth_any_ops = {
     svc_authany_wrap,
     svc_authany_wrap,
};

SVCAUTH svc_auth_any = {
     &svc_auth_any_ops,
     NULL,
};

static int
svc_authany_wrap(auth, xdrs, xfunc, xwhere)
   SVCAUTH *auth;
   XDR *xdrs;
   xdrproc_t xfunc;
   caddr_t xwhere;
{
     return (*xfunc)(xdrs, xwhere);
}
	


