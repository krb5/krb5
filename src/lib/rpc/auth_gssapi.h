/*
 * auth_gssapi.h, Protocol for GSS-API style authentication parameters for RPC
 * 
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 * 
 * $Log$
 * Revision 1.19  1996/08/14 00:01:34  tlyu
 * 	* getrpcent.c: Add PROTOTYPE and conditionalize function
 * 		prototypes.
 *
 * 	* xdr.h: Add PROTOTYPE and conditionalize function prototypes.
 *
 * 	* svc_auth_gssapi.c: Remove ANSI string concatenation, de-ANSI-fy
 *  		function definitions.
 *
 * 	* auth_gssapi_misc.c (auth_gssapi_display_status_1): Remove ANSI
 * 		string concatenation, de-ANSI-fy function definitions.
 *
 * 	* auth_gssapi.h: Add PROTOTYPE and conditionalize function
 * 		prototypes.
 *
 * 	* auth_gssapi.c (auth_gssapi_create): remove ANSI-ish string
 * 		concatenation, de-ANSI-fy function definitions.
 *
 * Revision 1.18  1996/07/22 20:39:41  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.17.4.1  1996/07/18 04:18:31  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.17.2.1  1996/06/20  23:35:44  marc
 * File added to the repository on a branch
 *
 * Revision 1.17  1996/05/12  06:11:38  marc
 * renamed lots of types: u_foo to unsigned foo, and foo32 to rpc_foo32.  This is to make autoconfiscation less painful.
 *
 * Revision 1.16  1996/01/31  19:16:16  grier
 * [secure/3570]
 * Remove (void *) casts to memcpy() args
 *
 * Revision 1.15  1995/12/28  17:54:34  jik
 * Don't define DEBUG_GSSAPI here.
 *
 * Revision 1.14  1995/12/13  14:03:01  grier
 * Longs to ints for Alpha
 *
 * Revision 1.13  1995/11/07  23:15:26  grier
 * memcpy() casts
 *
 * Revision 1.12  1995/05/25  18:35:59  bjaspan
 * [secure-rpc/3103] log misc errors from RPC
 *
 * Revision 1.11  1994/10/27  12:39:14  jik
 * [secure-rpc/2808: add credential versioning]
 *
 * Sandbox:
 *
 *  [secure-rpc/2808] add version field to client creds
 *
 * Revision 1.11  1994/10/26  20:04:00  bjaspan
 * [secure-rpc/2808] add version field to client creds
 *
 * Revision 1.10  1993/11/12  02:32:50  bjaspan
 * add badauth, don't use const_gss_OID
 *
 * Revision 1.9  1993/11/03  23:46:15  bjaspan
 * new log_badverf format
 *
 * Revision 1.8  1993/11/03  21:21:38  bjaspan
 * added log_badverf
 *
 * Revision 1.7  1993/11/03  01:29:56  bjaspan
 * add const to gss_nt_*
 *
 */

#define AUTH_GSSAPI_EXIT		0
#define AUTH_GSSAPI_INIT 		1
#define AUTH_GSSAPI_CONTINUE_INIT 	2
#define AUTH_GSSAPI_MSG 		3
#define AUTH_GSSAPI_DESTROY 		4

/*
 * Yuck.  Some sys/types.h files leak symbols
 */
#ifdef major
#undef major
#endif
#ifdef minor
#undef minor
#endif

/*
 * Make sure we have a definition for PROTOTYPE.
 */
#if !defined(PROTOTYPE)
#if defined(__STDC__) || defined(_MSDOS) || defined(_WIN32) || defined(__ultrix)
#define PROTOTYPE(x) x
#else
#define PROTOTYPE(x) ()
#endif
#endif

typedef struct _auth_gssapi_name {
     char *name;
     gss_OID type;
} auth_gssapi_name;

typedef struct _auth_gssapi_creds {
     rpc_u_int32 version;
     bool_t auth_msg;
     gss_buffer_desc client_handle;
} auth_gssapi_creds;

typedef struct _auth_gssapi_init_arg {
     rpc_u_int32 version;
     gss_buffer_desc token;
} auth_gssapi_init_arg;

typedef struct _auth_gssapi_init_res {
     rpc_u_int32 version;
     gss_buffer_desc client_handle;
     OM_uint32 gss_major, gss_minor;
     gss_buffer_desc token;
     gss_buffer_desc signed_isn;
} auth_gssapi_init_res;

typedef void (*auth_gssapi_log_badauth_func)
     PROTOTYPE((OM_uint32 major,
		OM_uint32 minor,
		struct sockaddr_in *raddr,
		caddr_t data));
   
typedef void (*auth_gssapi_log_badverf_func)
     PROTOTYPE((gss_name_t client,
		gss_name_t server,
		struct svc_req *rqst,
		struct rpc_msg *msg,
		caddr_t data));

typedef void (*auth_gssapi_log_miscerr_func)
     PROTOTYPE((struct svc_req *rqst,
		struct rpc_msg *msg,
		char *error,
		caddr_t data));

bool_t xdr_authgssapi_creds();
bool_t xdr_authgssapi_init_arg();
bool_t xdr_authgssapi_init_res();

bool_t auth_gssapi_wrap_data
PROTOTYPE((OM_uint32 *major, OM_uint32 *minor,
	   gss_ctx_id_t context, rpc_u_int32 seq_num, XDR
	   *out_xdrs, bool_t (*xdr_func)(), caddr_t
	   xdr_ptr));
bool_t auth_gssapi_unwrap_data
PROTOTYPE((OM_uint32 *major, OM_uint32 *minor,
	   gss_ctx_id_t context, rpc_u_int32 seq_num, XDR
	   *in_xdrs, bool_t (*xdr_func)(), caddr_t
	   xdr_ptr));

AUTH *auth_gssapi_create
PROTOTYPE((CLIENT *clnt,
	   OM_uint32 *major_status,
	   OM_uint32 *minor_status,
	   gss_cred_id_t claimant_cred_handle,
	   gss_name_t target_name,
	   gss_OID mech_type,
	   int req_flags,
	   OM_uint32 time_req,
	   gss_OID *actual_mech_type,
	   int *ret_flags,
	   OM_uint32 *time_rec));

AUTH *auth_gssapi_create_default
PROTOTYPE((CLIENT *clnt, char *service_name));

void auth_gssapi_display_status
PROTOTYPE((char *msg, OM_uint32 major,
	   OM_uint32 minor)); 
bool_t _svcauth_gssapi_set_name
PROTOTYPE((char *name, gss_OID name_type));

void _svcauth_set_log_badauth_func
PROTOTYPE((auth_gssapi_log_badauth_func func,
	   caddr_t data));
void _svcauth_set_log_badverf_func
PROTOTYPE((auth_gssapi_log_badverf_func func,
	   caddr_t data));
void _svcauth_set_log_miscerr_func
PROTOTYPE((auth_gssapi_log_miscerr_func func,
	   caddr_t data));

#define GSS_COPY_BUFFER(dest, src) { \
     (dest).length = (src).length; \
     (dest).value = (src).value; }

#define GSS_DUP_BUFFER(dest, src) { \
     (dest).length = (src).length; \
     (dest).value = (void *) malloc((dest).length); \
     memcpy((dest).value, (src).value, (dest).length); }

#define GSS_BUFFERS_EQUAL(b1, b2) (((b1).length == (b2).length) && \
				   !memcmp((b1).value,(b2).value,(b1.length)))

