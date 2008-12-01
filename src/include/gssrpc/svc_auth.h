/* @(#)svc_auth.h	2.1 88/07/29 4.0 RPCSRC */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*      @(#)svc_auth.h 1.6 86/07/16 SMI      */

/*
 * svc_auth.h, Service side of rpc authentication.
 * 
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

/*
 * Interface to server-side authentication flavors.
 */

#ifndef GSSRPC_SVC_AUTH_H
#define GSSRPC_SVC_AUTH_H

#include <gssapi/gssapi.h>

GSSRPC__BEGIN_DECLS

struct svc_req;

typedef struct SVCAUTH {
	struct svc_auth_ops {
		int	(*svc_ah_wrap)(struct SVCAUTH *, XDR *, xdrproc_t,
				       caddr_t);
		int	(*svc_ah_unwrap)(struct SVCAUTH *, XDR *, xdrproc_t,
					 caddr_t);
		int	(*svc_ah_destroy)(struct SVCAUTH *);
	} *svc_ah_ops;
	void * svc_ah_private;
} SVCAUTH;

#ifdef GSSRPC__IMPL

extern SVCAUTH svc_auth_none;

extern struct svc_auth_ops svc_auth_none_ops;
extern struct svc_auth_ops svc_auth_gssapi_ops;
extern struct svc_auth_ops svc_auth_gss_ops;

/*
 * Server side authenticator
 */
/* RENAMED: should be _authenticate. */
extern enum auth_stat gssrpc__authenticate(struct svc_req *rqst,
	struct rpc_msg *msg, bool_t *no_dispatch);

#define SVCAUTH_WRAP(auth, xdrs, xfunc, xwhere) \
     ((*((auth)->svc_ah_ops->svc_ah_wrap))(auth, xdrs, xfunc, xwhere))
#define SVCAUTH_UNWRAP(auth, xdrs, xfunc, xwhere) \
     ((*((auth)->svc_ah_ops->svc_ah_unwrap))(auth, xdrs, xfunc, xwhere))
#define SVCAUTH_DESTROY(auth) \
     ((*((auth)->svc_ah_ops->svc_ah_destroy))(auth))

/* no authentication */
/* RENAMED: should be _svcauth_none. */
enum auth_stat gssrpc__svcauth_none(struct svc_req *,
	struct rpc_msg *, bool_t *);
/* unix style (uid, gids) */
/* RENAMED: shoudl be _svcauth_unix. */
enum auth_stat gssrpc__svcauth_unix(struct svc_req *,
	struct rpc_msg *, bool_t *);
/* short hand unix style */
/* RENAMED: should be _svcauth_short. */
enum auth_stat gssrpc__svcauth_short(struct svc_req *,
	struct rpc_msg *, bool_t *);
/* GSS-API style */
/* RENAMED: should be _svcauth_gssapi. */
enum auth_stat gssrpc__svcauth_gssapi(struct svc_req *,
	struct rpc_msg *, bool_t *);
/* RPCSEC_GSS */
enum auth_stat gssrpc__svcauth_gss(struct svc_req *,
	struct rpc_msg *, bool_t *);

#endif /* defined(GSSRPC__IMPL) */

/*
 * Approved way of getting principal of caller
 */
char *svcauth_gss_get_principal(SVCAUTH *auth);
/*
 * Approved way of setting server principal
 */
bool_t svcauth_gss_set_svc_name(gss_name_t name);

GSSRPC__END_DECLS

#endif /* !defined(GSSRPC_SVC_AUTH_H) */
