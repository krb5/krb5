/*
  auth_gss.c

  RPCSEC_GSS client routines.
  
  Copyright (c) 2000 The Regents of the University of Michigan.
  All rights reserved.

  Copyright (c) 2000 Dug Song <dugsong@UMICH.EDU>.
  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. Neither the name of the University nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  Id: auth_gss.c,v 1.35 2002/10/15 21:25:25 kwc Exp
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <gssrpc/types.h>
#include <gssrpc/xdr.h>
#include <gssrpc/auth.h>
#include <gssrpc/auth_gss.h>
#include <gssrpc/clnt.h>
#include <netinet/in.h>
#ifdef HAVE_HEIMDAL
#include <gssapi.h>
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE
#else
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#endif

#ifdef DEBUG_GSSAPI
int auth_debug_gss = DEBUG_GSSAPI;
int misc_debug_gss = DEBUG_GSSAPI;
#endif

static void	authgss_nextverf(AUTH *);
static bool_t	authgss_marshal(AUTH *, XDR *);
static bool_t	authgss_refresh(AUTH *, struct rpc_msg *);
static bool_t	authgss_validate(AUTH *, struct opaque_auth *);
static void	authgss_destroy(AUTH *);
static void	authgss_destroy_context(AUTH *);
static bool_t	authgss_wrap(AUTH *, XDR *, xdrproc_t, caddr_t);
static bool_t	authgss_unwrap(AUTH *, XDR *, xdrproc_t, caddr_t);


/*
 * from mit-krb5-1.2.1 mechglue/mglueP.h:
 * Array of context IDs typed by mechanism OID
 */
typedef struct gss_union_ctx_id_t {
  gss_OID     mech_type;
  gss_ctx_id_t    internal_ctx_id;
} gss_union_ctx_id_desc, *gss_union_ctx_id_t;

static struct auth_ops authgss_ops = {
	authgss_nextverf,
	authgss_marshal,
	authgss_validate,
	authgss_refresh,
	authgss_destroy,
	authgss_wrap,
	authgss_unwrap
};

#ifdef DEBUG

/* useful as i add more mechanisms */
void
print_rpc_gss_sec(struct rpc_gss_sec *ptr)
{
#if HAVE_HEIMDAL
	int i;
	char *p;

	log_debug("rpc_gss_sec:\n");
	if(ptr->mech == NULL)
		log_debug("NULL gss_OID mech\n");
	else {
		log_debug("     gss_OID len: %d\n gss_OID elements:",
			ptr->mech->length);
		p = (char *)ptr->mech->elements;
		log_debug("     ");
		for(i=0;i<ptr->mech->length;i++)
			log_debug("%u", (u_char)*p++);
		log_debug("\n");
	}
	log_debug("     qop: %d\n",ptr->qop);
	log_debug("     service: %d\n",ptr->svc);
#else
	OM_uint32 min_stat;
	gss_buffer_desc msg;

	if (ptr->mech == NULL)
		log_debug("rpc_gss_sec: mech NULL, qop %d, svc %d",
			  ptr->qop, ptr->svc);
	else {
		gss_oid_to_str(&min_stat, ptr->mech, &msg);

		log_debug("rpc_gss_sec: mech %.*s, qop %d, svc %d",
			  msg.length, (char *)msg.value,
			  ptr->qop, ptr->svc);

		gss_release_buffer(&min_stat, &msg);
	}
#endif
}
#endif /*DEBUG*/

/* Krb 5 default mechanism oid */
#define KRB5OID  "1.2.840.113554.1.2.2"

#define g_OID_equal(o1,o2) \
   (((o1)->length == (o2)->length) && \
    ((o1)->elements != 0) && ((o2)->elements != 0) && \
    (memcmp((o1)->elements,(o2)->elements,(int) (o1)->length) == 0))

extern const gss_OID_desc * const gss_mech_krb5;
#ifdef SPKM
extern const gss_OID_desc * const gss_mech_spkm3;
#endif /*SPKM*/

/* from kerberos source, gssapi_krb5.c */
static gss_OID_desc krb5oid = 
   {9, "\052\206\110\206\367\022\001\002\002"};

#if SPKM
static gss_OID_desc spkm3oid = 
   {7, "\052\006\001\005\005\001\003"};
#endif /*SPKM*/

struct rpc_gss_data {
	bool_t			 established;	/* context established */
	bool_t			 inprogress;
  gss_buffer_desc      gc_wire_verf; /* save GSS_S_COMPLETE NULL RPC verfier 
                                   * to process at end of context negotiation*/
	CLIENT			*clnt;		/* client handle */
	gss_name_t		 name;		/* service name */
	struct rpc_gss_sec	 sec;		/* security tuple */
	gss_ctx_id_t		 ctx;		/* context id */
	struct rpc_gss_cred	 gc;		/* client credentials */
	u_int			 win;		/* sequence window */
};

#define	AUTH_PRIVATE(auth)	((struct rpc_gss_data *)auth->ah_private)

static struct timeval AUTH_TIMEOUT = { 25, 0 };

AUTH *
authgss_create(CLIENT *clnt, gss_name_t name, struct rpc_gss_sec *sec)
{
	AUTH			*auth, *save_auth;
	struct rpc_gss_data	*gd;

	log_debug("in authgss_create()");
	
	memset(&rpc_createerr, 0, sizeof(rpc_createerr));
	
	if ((auth = calloc(sizeof(*auth), 1)) == NULL) {
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = ENOMEM;
		return (NULL);
	}
	if ((gd = calloc(sizeof(*gd), 1)) == NULL) {
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = ENOMEM;
		free(auth);
		return (NULL);
	}
	gd->clnt = clnt;
	gd->name = name;
	gd->ctx = GSS_C_NO_CONTEXT;
	gd->sec = *sec;

	gd->gc.gc_v = RPCSEC_GSS_VERSION;
	gd->gc.gc_proc = RPCSEC_GSS_INIT;
	gd->gc.gc_svc = gd->sec.svc;
	
	auth->ah_ops = &authgss_ops;
	auth->ah_private = (caddr_t)gd;
	
	save_auth = clnt->cl_auth;
	clnt->cl_auth = auth;

	if (!authgss_refresh(auth, NULL))
		auth = NULL;
	
	clnt->cl_auth = save_auth;
	
	log_debug("authgss_create returning auth 0x%08x", auth);
	return (auth);
}

AUTH *
authgss_create_default(CLIENT *clnt, char *service, struct rpc_gss_sec *sec)
{
	AUTH			*auth;
	OM_uint32		 maj_stat = 0, min_stat = 0;
	gss_buffer_desc		 sname;
	gss_name_t		 name;

	log_debug("in authgss_create_default()");
	

	sname.value = service;
	sname.length = strlen(service);
	
	maj_stat = gss_import_name(&min_stat, &sname,
		(gss_OID)gss_nt_service_name,
		&name);

	if (maj_stat != GSS_S_COMPLETE) {
		log_status("gss_import_name", maj_stat, min_stat);
		rpc_createerr.cf_stat = RPC_AUTHERROR;
		return (NULL);
	}

	auth = authgss_create(clnt, name, sec);
	
 	if(auth)
 		gss_release_name(&min_stat, &name);
	
	log_debug("authgss_create_default returning auth 0x%08x", auth);
	return (auth);
}

static void
authgss_nextverf(AUTH *auth)
{
	log_debug("in authgss_nextverf()\n");
	/* no action necessary */
}

static bool_t
authgss_marshal(AUTH *auth, XDR *xdrs)
{
	XDR			 tmpxdrs;
	char			 tmp[MAX_AUTH_BYTES];
	struct rpc_gss_data	*gd;
	gss_buffer_desc		 rpcbuf, checksum;
	OM_uint32		 maj_stat, min_stat;
	bool_t			 xdr_stat;
	
	log_debug("in authgss_marshal()");
	
	gd = AUTH_PRIVATE(auth);

	if (gd->established)
		gd->gc.gc_seq++;
	
	xdrmem_create(&tmpxdrs, tmp, sizeof(tmp), XDR_ENCODE);
	
	if (!xdr_rpc_gss_cred(&tmpxdrs, &gd->gc)) {
		XDR_DESTROY(&tmpxdrs);
		return (FALSE);
	}
	auth->ah_cred.oa_flavor = RPCSEC_GSS;
	auth->ah_cred.oa_base = tmp;
	auth->ah_cred.oa_length = XDR_GETPOS(&tmpxdrs);
	
	XDR_DESTROY(&tmpxdrs);
	
	if (!xdr_opaque_auth(xdrs, &auth->ah_cred))
		return (FALSE);
	
	if (gd->gc.gc_proc == RPCSEC_GSS_INIT ||
	    gd->gc.gc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		return (xdr_opaque_auth(xdrs, &gssrpc__null_auth));
	}
	/* Checksum serialized RPC header, up to and including credential. */
	rpcbuf.length = XDR_GETPOS(xdrs);
	XDR_SETPOS(xdrs, 0);
	rpcbuf.value = XDR_INLINE(xdrs, rpcbuf.length);
	
	maj_stat = gss_get_mic(&min_stat, gd->ctx, gd->sec.qop,
			    &rpcbuf, &checksum);

	if (maj_stat != GSS_S_COMPLETE) {
		log_status("gss_get_mic", maj_stat, min_stat);
		if (maj_stat == GSS_S_CONTEXT_EXPIRED) {
			gd->established = FALSE;
			authgss_destroy_context(auth);
		}
		return (FALSE);
	}
	auth->ah_verf.oa_flavor = RPCSEC_GSS;
	auth->ah_verf.oa_base = checksum.value;
	auth->ah_verf.oa_length = checksum.length;
	
	xdr_stat = xdr_opaque_auth(xdrs, &auth->ah_verf);
	gss_release_buffer(&min_stat, &checksum);
	
	return (xdr_stat);
}

static bool_t
authgss_validate(AUTH *auth, struct opaque_auth *verf)
{
	struct rpc_gss_data	*gd;
	u_int			 num, qop_state;
	gss_buffer_desc		 signbuf, checksum;
	OM_uint32		 maj_stat, min_stat;

	log_debug("in authgss_validate()");
	
	gd = AUTH_PRIVATE(auth);

	if (gd->established == FALSE) {
		/* would like to do this only on NULL rpc - gc->established is good enough.
		 * save the on the wire verifier to validate last INIT phase packet
		 * after decode if the major status is GSS_S_COMPLETE 
		 */
		if ((gd->gc_wire_verf.value = mem_alloc(verf->oa_length)) == NULL) {
			fprintf(stderr, "gss_validate: out of memory\n");
			return (FALSE);
		}
		memcpy(gd->gc_wire_verf.value, verf->oa_base, verf->oa_length);
		gd->gc_wire_verf.length = verf->oa_length;
		return (TRUE);
  	}

	if (gd->gc.gc_proc == RPCSEC_GSS_INIT ||
	    gd->gc.gc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		num = htonl(gd->win);
	}
	else num = htonl(gd->gc.gc_seq);
	
	signbuf.value = &num;
	signbuf.length = sizeof(num);
	
	checksum.value = verf->oa_base;
	checksum.length = verf->oa_length;
	
	maj_stat = gss_verify_mic(&min_stat, gd->ctx, &signbuf,
				  &checksum, &qop_state);
	if (maj_stat != GSS_S_COMPLETE || qop_state != gd->sec.qop) {
		log_status("gss_verify_mic", maj_stat, min_stat);
		if (maj_stat == GSS_S_CONTEXT_EXPIRED) {
			gd->established = FALSE;
			authgss_destroy_context(auth);
		}
		return (FALSE);
	}
	return (TRUE);
}

static bool_t
authgss_refresh(AUTH *auth, struct rpc_msg *msg)
{
	struct rpc_gss_data	*gd;
	struct rpc_gss_init_res	 gr;
	gss_buffer_desc		*recv_tokenp, send_token;
	OM_uint32		 maj_stat, min_stat, call_stat, ret_flags, req_flags=0;

	log_debug("in authgss_refresh()");
	
	gd = AUTH_PRIVATE(auth);
	
	if (gd->established || gd->inprogress)
		return (TRUE);
	
	/* GSS context establishment loop. */
	memset(&gr, 0, sizeof(gr));
	recv_tokenp = GSS_C_NO_BUFFER;
	
#ifdef DEBUG
	print_rpc_gss_sec(&gd->sec);
#endif /*DEBUG*/

	if (g_OID_equal(gd->sec.mech, &krb5oid))
		req_flags |= GSS_C_MUTUAL_FLAG;
  
#ifdef SPKM
	if (g_OID_equal(gd->sec.mech, gss_mech_spkm3))
		req_flags |= GSS_C_ANON_FLAG;
#endif /*SPKM*/
   
	for (;;) {
		gd->inprogress = TRUE;
		maj_stat = gss_init_sec_context(&min_stat,
						GSS_C_NO_CREDENTIAL,
						&gd->ctx,
						gd->name,
						gd->sec.mech,
						req_flags,
						0,		/* time req */
						NULL,		/* channel */
						recv_tokenp,
						NULL,		/* used mech */
						&send_token,
						&ret_flags,
						NULL);		/* time rec */
		
		log_status("gss_init_sec_context", maj_stat, min_stat);
		if (recv_tokenp != GSS_C_NO_BUFFER) {
			gss_release_buffer(&min_stat, &gr.gr_token);
			recv_tokenp = GSS_C_NO_BUFFER;
		}
		if (maj_stat != GSS_S_COMPLETE &&
		    maj_stat != GSS_S_CONTINUE_NEEDED) {
			log_status("gss_init_sec_context (error)", maj_stat, min_stat);
			break;
		}
		if (send_token.length != 0) {
			memset(&gr, 0, sizeof(gr));
			
			call_stat = clnt_call(gd->clnt, NULLPROC,
					      xdr_rpc_gss_init_args,
					      &send_token,
					      xdr_rpc_gss_init_res,
					      (caddr_t)&gr, AUTH_TIMEOUT);
			
			gss_release_buffer(&min_stat, &send_token);

			log_debug("authgss_refresh: call_stat=%d", call_stat);
			log_debug("%s", clnt_sperror(gd->clnt, "authgss_refresh"));
			if (call_stat != RPC_SUCCESS ||
			    (gr.gr_major != GSS_S_COMPLETE &&
			     gr.gr_major != GSS_S_CONTINUE_NEEDED))
				break;
			
			if (gr.gr_ctx.length != 0) {
				if (gd->gc.gc_ctx.value)
					gss_release_buffer(&min_stat,
							   &gd->gc.gc_ctx);
				gd->gc.gc_ctx = gr.gr_ctx;
			}
			if (gr.gr_token.length != 0) {
				if (maj_stat != GSS_S_CONTINUE_NEEDED)
					break;
				recv_tokenp = &gr.gr_token;
			}
			gd->gc.gc_proc = RPCSEC_GSS_CONTINUE_INIT;
		}
		
		/* GSS_S_COMPLETE => check gss header verifier, usually checked in
		 * gss_validate
		 */
		if (maj_stat == GSS_S_COMPLETE) {
			gss_buffer_desc   bufin;
			gss_buffer_desc   bufout;
			u_int seq, qop_state = 0;

			seq = htonl(gr.gr_win);
			bufin.value = (u_char *)&seq;
			bufin.length = sizeof(seq);
			bufout.value = (u_char *)gd->gc_wire_verf.value;
			bufout.length = gd->gc_wire_verf.length;

			log_debug("authgss_refresh: GSS_S_COMPLETE: calling verify_mic");
			maj_stat = gss_verify_mic(&min_stat,gd->ctx,
				&bufin, &bufout, &qop_state);

			if (maj_stat != GSS_S_COMPLETE || qop_state != gd->sec.qop) {
				log_status("gss_verify_mic", maj_stat, min_stat);
				gss_release_buffer(&min_stat, &gd->gc_wire_verf);
				if (maj_stat == GSS_S_CONTEXT_EXPIRED) {
					gd->established = FALSE;
					authgss_destroy_context(auth);
				}
				return (FALSE);
			}
			gss_release_buffer(&min_stat, &gd->gc_wire_verf);
			gd->established = TRUE;
			gd->inprogress = FALSE;
			gd->gc.gc_proc = RPCSEC_GSS_DATA;
			gd->gc.gc_seq = 0;
			gd->win = gr.gr_win;
			break;
		}
	}
	log_status("authgss_refresh: at end of context negotiation", maj_stat, min_stat);
	/* End context negotiation loop. */
	if (gd->gc.gc_proc != RPCSEC_GSS_DATA) {
		log_debug("authgss_refresh: returning ERROR (gc_proc %d)", gd->gc.gc_proc);
		if (gr.gr_token.length != 0)
			gss_release_buffer(&min_stat, &gr.gr_token);
		
		authgss_destroy(auth);
		auth = NULL;
		rpc_createerr.cf_stat = RPC_AUTHERROR;
		
		return (FALSE);
	}
	log_debug("authgss_refresh: returning SUCCESS");
	return (TRUE);
}

bool_t
authgss_service(AUTH *auth, int svc)
{
	struct rpc_gss_data	*gd;

	log_debug("in authgss_service()");

	if (!auth)
		return(FALSE);
	gd = AUTH_PRIVATE(auth);
	if (!gd || !gd->established)
		return (FALSE);
	gd->sec.svc = svc;
	gd->gc.gc_svc = svc;
	return (TRUE);
}

static void
authgss_destroy_context(AUTH *auth)
{
	struct rpc_gss_data	*gd;
	OM_uint32		 min_stat;
	enum clnt_stat		 callstat;

	log_debug("in authgss_destroy_context()");
	
	gd = AUTH_PRIVATE(auth);
	
	if (gd->gc.gc_ctx.length != 0) {
		if (gd->established) {
			gd->gc.gc_proc = RPCSEC_GSS_DESTROY;
			callstat = clnt_call(gd->clnt, NULLPROC,
					     xdr_void, NULL,
					     xdr_void, NULL,
					     AUTH_TIMEOUT);
			log_debug("%s",
				  clnt_sperror(gd->clnt,
					       "authgss_destroy_context"));
		}
		gss_release_buffer(&min_stat, &gd->gc.gc_ctx);
		/* XXX ANDROS check size of context  - should be 8 */
		memset(&gd->gc.gc_ctx, 0, sizeof(gd->gc.gc_ctx));
	}
	if (gd->ctx != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&min_stat, &gd->ctx, NULL);
		gd->ctx = GSS_C_NO_CONTEXT;
	}
	gd->established = FALSE;

	log_debug("finished authgss_destroy_context()");
}

static void
authgss_destroy(AUTH *auth)
{
	struct rpc_gss_data	*gd;
	OM_uint32		 min_stat;
	
	log_debug("in authgss_destroy()");
	
	gd = AUTH_PRIVATE(auth);
	
	authgss_destroy_context(auth);
	
	if (gd->name != GSS_C_NO_NAME)
		gss_release_name(&min_stat, &gd->name);
#if 0
#ifdef HAVE_HEIMDAL
		gss_release_name(&min_stat, &gd->name);
#else
		gss_release_name(&min_stat, gd->name);
#endif
#endif
	free(gd);
	free(auth);
}

bool_t
authgss_wrap(AUTH *auth, XDR *xdrs, xdrproc_t xdr_func, caddr_t xdr_ptr)
{
	struct rpc_gss_data	*gd;

	log_debug("in authgss_wrap()");
	
	gd = AUTH_PRIVATE(auth);

	if (!gd->established || gd->sec.svc == RPCSEC_GSS_SVC_NONE) {
		return ((*xdr_func)(xdrs, xdr_ptr));
	}
	return (xdr_rpc_gss_data(xdrs, xdr_func, xdr_ptr,
				 gd->ctx, gd->sec.qop,
				 gd->sec.svc, gd->gc.gc_seq));
}

bool_t
authgss_unwrap(AUTH *auth, XDR *xdrs, xdrproc_t xdr_func, caddr_t xdr_ptr)
{
	struct rpc_gss_data	*gd;

	log_debug("in authgss_unwrap()");
	
	gd = AUTH_PRIVATE(auth);
	
	if (!gd->established || gd->sec.svc == RPCSEC_GSS_SVC_NONE) {
		return ((*xdr_func)(xdrs, xdr_ptr));
	}
	return (xdr_rpc_gss_data(xdrs, xdr_func, xdr_ptr,
				 gd->ctx, gd->sec.qop,
				 gd->sec.svc, gd->gc.gc_seq));
}
