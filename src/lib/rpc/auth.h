/* @(#)auth.h	2.3 88/08/07 4.0 RPCSRC; from 1.17 88/02/08 SMI */
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

/*
 * auth.h, Authentication interface.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * The data structures are completely opaque to the client.  The client
 * is required to pass a AUTH * to routines that create rpc
 * "sessions".
 */


#include <gssrpc/xdr.h>

#define MAX_AUTH_BYTES	400
#define MAXNETNAMELEN	255	/* maximum length of network user's name */

/*
 * Status returned from authentication check
 */
enum auth_stat {
	AUTH_OK=0,
	/*
	 * failed at remote end
	 */
	AUTH_BADCRED=1,			/* bogus credentials (seal broken) */
	AUTH_REJECTEDCRED=2,		/* client should begin new session */
	AUTH_BADVERF=3,			/* bogus verifier (seal broken) */
	AUTH_REJECTEDVERF=4,		/* verifier expired or was replayed */
	AUTH_TOOWEAK=5,			/* rejected due to security reasons */
	/*
	 * failed locally
	*/
	AUTH_INVALIDRESP=6,		/* bogus response verifier */
	AUTH_FAILED=7			/* some unknown reason */
};

union des_block {
#if 0 /* XXX nothing uses this, anyway */
	struct {
		rpc_u_int32 high;
		rpc_u_int32 low;
	} key;
#endif
	char c[8];
};
typedef union des_block des_block;
#define xdr_des_block	gssrpc_xdr_des_block
extern bool_t xdr_des_block(XDR *, des_block *);

/*
 * Authentication info.  Opaque to client.
 */
struct opaque_auth {
	enum_t	oa_flavor;		/* flavor of auth */
	caddr_t	oa_base;		/* address of more auth stuff */
	unsigned int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
};


/*
 * Auth handle, interface to client side authenticators.
 */
struct rpc_msg;

typedef struct __rpc_auth {
	struct	opaque_auth	ah_cred;
	struct	opaque_auth	ah_verf;
	union	des_block	ah_key;
	struct auth_ops {
		void	(*ah_nextverf)(struct __rpc_auth *);
	        /* nextverf & serialize */
		int	(*ah_marshal)(struct __rpc_auth *, XDR *);
	        /* validate varifier */
		int	(*ah_validate)(struct __rpc_auth *,
				       struct opaque_auth *);
	        /* refresh credentials */
		int	(*ah_refresh)(struct __rpc_auth *, struct rpc_msg *);
	        /* destroy this structure */
		void	(*ah_destroy)(struct __rpc_auth *);
		/* encode data for wire */
		int     (*ah_wrap)(struct __rpc_auth *, XDR *, 
				   xdrproc_t, caddr_t);
	        /* decode data from wire */
  	        int	(*ah_unwrap)(struct __rpc_auth *, XDR *, 
				     xdrproc_t, caddr_t);	
	} *ah_ops;
	void *ah_private;
} AUTH;


/*
 * Authentication ops.
 * The ops and the auth handle provide the interface to the authenticators.
 *
 * AUTH	*auth;
 * XDR	*xdrs;
 * struct opaque_auth verf;
 */
#define AUTH_NEXTVERF(auth)		\
		((*((auth)->ah_ops->ah_nextverf))(auth))
#define auth_nextverf(auth)		\
		((*((auth)->ah_ops->ah_nextverf))(auth))

#define AUTH_MARSHALL(auth, xdrs)	\
		((*((auth)->ah_ops->ah_marshal))(auth, xdrs))
#define auth_marshall(auth, xdrs)	\
		((*((auth)->ah_ops->ah_marshal))(auth, xdrs))

#define AUTH_VALIDATE(auth, verfp)	\
		((*((auth)->ah_ops->ah_validate))((auth), verfp))
#define auth_validate(auth, verfp)	\
		((*((auth)->ah_ops->ah_validate))((auth), verfp))

#define AUTH_REFRESH(auth, msg)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg))
#define auth_refresh(auth, msg)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg))

#define AUTH_WRAP(auth, xdrs, xfunc, xwhere)		\
		((*((auth)->ah_ops->ah_wrap))(auth, xdrs, \
					      xfunc, xwhere))
#define AUTH_wrap(auth, xdrs, xfunc, xwhere)		\
		((*((auth)->ah_ops->ah_wrap))(auth, xdrs, \
					      xfunc, xwhere))
#define AUTH_UNWRAP(auth, xdrs, xfunc, xwhere)		\
		((*((auth)->ah_ops->ah_unwrap))(auth, xdrs, \
					      xfunc, xwhere))
#define AUTH_unwrap(auth, xdrs, xfunc, xwhere)		\
		((*((auth)->ah_ops->ah_unwrap))(auth, xdrs, \
					      xfunc, xwhere))

#define AUTH_DESTROY(auth)		\
		((*((auth)->ah_ops->ah_destroy))(auth))
#define auth_destroy(auth)		\
		((*((auth)->ah_ops->ah_destroy))(auth))


#define _null_auth	_gssrpc_null_auth
extern struct opaque_auth _null_auth;


/*
 * These are the various implementations of client side authenticators.
 */

/*
 * Any style authentication.  These routines can be used by any
 * authentication style that does not use the wrap/unwrap functions.
 */

#define authany_wrap	gssrpc_authany_wrap
#define authany_unwrap	gssrpc_authany_unwrap

int authany_wrap(AUTH *, XDR *, xdrproc_t, caddr_t), authany_unwrap();
	
/*
 * Unix style authentication
 * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
 *	char *machname;
 *	int uid;
 *	int gid;
 *	int len;
 *	int *aup_gids;
 */
#define authunix_create		gssrpc_authunix_create
#define authunix_create_default	gssrpc_authunix_create_default
#define authnone_create		gssrpc_authnone_create
#define authdes_create		gssrpc_authdes_create

extern AUTH *authunix_create(char *machname, int uid, int gid, int len,
			     int *aup_gids);
extern AUTH *authunix_create_default(void);	/* takes no parameters */
extern AUTH *authnone_create(void);		/* takes no parameters */
extern AUTH *authdes_create();

/*
 * GSS-API style authentication:
 * see <rpc/auth_gssapi.h>
 */

#define AUTH_NONE	0		/* no authentication */
#define	AUTH_NULL	0		/* backward compatibility */
#define	AUTH_UNIX	1		/* unix style (uid, gids) */
#define	AUTH_SHORT	2		/* short hand unix style */
#define AUTH_DES	3		/* des style (encrypted timestamps) */
#define AUTH_GSSAPI	300001		/* GSS-API style */

/*
 * BACKWARDS COMPATIBILIY!  OpenV*Secure 1.0 had AUTH_GSSAPI == 4.  We
 * need to accept this value until 1.0 is dead.
 */
#define AUTH_GSSAPI_COMPAT		4

/*
 * XDR an opaque authentication struct.
 */
#define xdr_opaque_auth	   gssrpc_xdr_opaque_auth

extern bool_t xdr_opaque_auth (XDR *, struct opaque_auth *);
