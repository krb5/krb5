/* @(#)rpc.h	2.3 88/08/10 4.0 RPCSRC; from 1.9 88/02/08 SMI */
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
 * rpc.h, Just includes the billions of rpc header files necessary to
 * do remote procedure calling.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */
#ifndef GSSRPC_RPC_H
#define GSSRPC_RPC_H

#include <gssrpc/types.h>		/* some typedefs */
#include <netinet/in.h>

/* external data representation interfaces */
#include <gssrpc/xdr.h>		/* generic (de)serializer */

/* Client side only authentication */
#include <gssrpc/auth.h>		/* generic authenticator (client side) */

/* Client side (mostly) remote procedure call */
#include <gssrpc/clnt.h>		/* generic rpc stuff */

/* semi-private protocol headers */
#include <gssrpc/rpc_msg.h>	/* protocol for rpc messages */
#include <gssrpc/auth_unix.h>	/* protocol for unix style cred */
#include <gssrpc/auth_gss.h>	/* RPCSEC_GSS */
/*
 *  Uncomment-out the next line if you are building the rpc library with
 *  DES Authentication (see the README file in the secure_rpc/ directory).
 */
#if 0
#include <gssrpc/auth_des.h>	protocol for des style cred
#endif

/* Server side only remote procedure callee */
#include <gssrpc/svc_auth.h>	/* service side authenticator */
#include <gssrpc/svc.h>		/* service manager and multiplexer */

/*
 * Punt the rpc/netdb.h everywhere because it just makes things much more
 * difficult.  We don't use the *rpcent functions anyway.
 */
#if 0
/*
 * COMMENT OUT THE NEXT INCLUDE IF RUNNING ON SUN OS OR ON A VERSION
 * OF UNIX BASED ON NFSSRC.  These systems will already have the structures
 * defined by <rpc/netdb.h> included in <netdb.h>.
 */
/* routines for parsing /etc/rpc */
#if 0 /* netdb.h already included in rpc/types.h */
#include <netdb.h>
#endif

#include <gssrpc/netdb.h>	/* structures and routines to parse /etc/rpc */
#endif

/*
 * get the local host's IP address without consulting
 * name service library functions
 */
GSSRPC__BEGIN_DECLS
extern int get_myaddress(struct sockaddr_in *);
extern int bindresvport(int, struct sockaddr_in *);
extern int callrpc(char *, rpcprog_t, rpcvers_t, rpcproc_t, xdrproc_t,
		   char *, xdrproc_t , char *);
extern int getrpcport(char *, rpcprog_t, rpcvers_t, rpcprot_t);
extern int gssrpc__rpc_dtablesize(void);
GSSRPC__END_DECLS

#endif /* !defined(GSSRPC_RPC_H) */
