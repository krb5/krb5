/* @(#)pmap_clnt.h	2.1 88/07/29 4.0 RPCSRC; from 1.11 88/02/08 SMI */
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
 * pmap_clnt.h
 * Supplies C routines to get to portmap services.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

/*
 * Usage:
 *	success = pmap_set(program, version, protocol, port);
 *	success = pmap_unset(program, version);
 *	port = pmap_getport(address, program, version, protocol);
 *	head = pmap_getmaps(address);
 *	clnt_stat = pmap_rmtcall(address, program, version, procedure,
 *		xdrargs, argsp, xdrres, resp, tout, port_ptr)
 *		(works for udp only.) 
 * 	clnt_stat = clnt_broadcast(program, version, procedure,
 *		xdrargs, argsp,	xdrres, resp, eachresult)
 *		(like pmap_rmtcall, except the call is broadcasted to all
 *		locally connected nets.  For each valid response received,
 *		the procedure eachresult is called.  Its form is:
 *	done = eachresult(resp, raddr)
 *		bool_t done;
 *		caddr_t resp;
 *		struct sockaddr_in raddr;
 *		where resp points to the results of the call and raddr is the
 *		address if the responder to the broadcast.
 */

#define pmap_set	gssrpc_pmap_set
#define pmap_unset	gssrpc_pmap_unset
#define pmap_getmaps	gssrpc_pmap_getmaps
#define pmap_rmtcall	gssrpc_pmap_rmtcall
#define clnt_broadcast	gssrpc_clnt_broadcast
#define pmap_getport	gssrpc_pmap_getport

extern bool_t		pmap_set(rpc_u_int32, rpc_u_int32, int, 
				 int);
extern bool_t		pmap_unset(rpc_u_int32, rpc_u_int32);
extern struct pmaplist	*pmap_getmaps(struct sockaddr_in *);
enum clnt_stat		pmap_rmtcall(struct sockaddr_in *, rpc_u_int32, 
				     rpc_u_int32, rpc_u_int32, xdrproc_t, 
				     caddr_t, xdrproc_t, caddr_t, 
				     struct timeval, rpc_u_int32 *);

typedef bool_t (*resultproc_t)(caddr_t, struct sockaddr_in *);

enum clnt_stat		clnt_broadcast(rpc_u_int32, rpc_u_int32, rpc_u_int32,
				       xdrproc_t, caddr_t, xdrproc_t,
				       caddr_t, resultproc_t);
extern unsigned short		pmap_getport(struct sockaddr_in *, 
					     rpc_u_int32, 
					     rpc_u_int32, rpc_u_int32);
