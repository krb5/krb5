/*
 * auth_gssapi.h, Protocol for GSS-API style authentication parameters for RPC
 * 
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
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

