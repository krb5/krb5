#include "k5-int.h"
#include "auth_con.h"

static krb5_error_code
actx_copy_addr(krb5_context context, const krb5_address *inad, krb5_address **outad)
{
    krb5_address *tmpad;

    if (!(tmpad = (krb5_address *)malloc(sizeof(*tmpad))))
	return ENOMEM;
#ifdef HAVE_C_STRUCTURE_ASSIGNMENT
    *tmpad = *inad;
#else
    memcpy(tmpad, inad, sizeof(krb5_address));
#endif
    if (!(tmpad->contents = (krb5_octet *)malloc(inad->length))) {
	krb5_xfree(tmpad);
	return ENOMEM;
    }
    memcpy((char *)tmpad->contents, (char *)inad->contents, inad->length);
    *outad = tmpad;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_init(krb5_context context, krb5_auth_context *auth_context)
{
    *auth_context =
            (krb5_auth_context)malloc(sizeof(struct _krb5_auth_context));
    if (!*auth_context)
	    return ENOMEM;
    
    memset(*auth_context, 0, sizeof(struct _krb5_auth_context));

    /* Default flags, do time not seq */
    (*auth_context)->auth_context_flags = 
	    KRB5_AUTH_CONTEXT_DO_TIME |  KRB5_AUTH_CONN_INITIALIZED;

    (*auth_context)->req_cksumtype = context->default_ap_req_sumtype;
    (*auth_context)->safe_cksumtype = context->default_safe_sumtype;
    (*auth_context) -> checksum_func = NULL;
    (*auth_context)->checksum_func_data = NULL;
    (*auth_context)->magic = KV5M_AUTH_CONTEXT;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_free(krb5_context context, krb5_auth_context auth_context)
{
    if (auth_context->local_addr) 
	krb5_free_address(context, auth_context->local_addr);
    if (auth_context->remote_addr) 
	krb5_free_address(context, auth_context->remote_addr);
    if (auth_context->local_port) 
	krb5_free_address(context, auth_context->local_port);
    if (auth_context->remote_port) 
	krb5_free_address(context, auth_context->remote_port);
    if (auth_context->authentp) 
	krb5_free_authenticator(context, auth_context->authentp);
    if (auth_context->keyblock) 
	krb5_free_keyblock(context, auth_context->keyblock);
    if (auth_context->send_subkey) 
	krb5_free_keyblock(context, auth_context->send_subkey);
    if (auth_context->recv_subkey) 
	krb5_free_keyblock(context, auth_context->recv_subkey);
    if (auth_context->rcache)
	krb5_rc_close(context, auth_context->rcache);
    if (auth_context->permitted_etypes)
	krb5_xfree(auth_context->permitted_etypes);
    free(auth_context);
    return 0;
}

krb5_error_code
krb5_auth_con_setaddrs(krb5_context context, krb5_auth_context auth_context, krb5_address *local_addr, krb5_address *remote_addr)
{
    krb5_error_code	retval;

    /* Free old addresses */
    if (auth_context->local_addr)
	(void) krb5_free_address(context, auth_context->local_addr);
    if (auth_context->remote_addr)
	(void) krb5_free_address(context, auth_context->remote_addr);

    retval = 0;
    if (local_addr)
	retval = actx_copy_addr(context,
				local_addr,
				&auth_context->local_addr);
    else
	auth_context->local_addr = NULL;

    if (!retval && remote_addr)
	retval = actx_copy_addr(context,
				remote_addr,
				&auth_context->remote_addr);
    else
	auth_context->remote_addr = NULL;

    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getaddrs(krb5_context context, krb5_auth_context auth_context, krb5_address **local_addr, krb5_address **remote_addr)
{
    krb5_error_code	retval;

    retval = 0;
    if (local_addr && auth_context->local_addr) {
	retval = actx_copy_addr(context,
				auth_context->local_addr,
				local_addr);
    }
    if (!retval && (remote_addr) && auth_context->remote_addr) {
	retval = actx_copy_addr(context,
				auth_context->remote_addr,
				remote_addr);
    }
    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_setports(krb5_context context, krb5_auth_context auth_context, krb5_address *local_port, krb5_address *remote_port)
{
    krb5_error_code	retval;

    /* Free old addresses */
    if (auth_context->local_port)
	(void) krb5_free_address(context, auth_context->local_port);
    if (auth_context->remote_port)
	(void) krb5_free_address(context, auth_context->remote_port);

    retval = 0;
    if (local_port)
	retval = actx_copy_addr(context,
				local_port,
				&auth_context->local_port);
    else
	auth_context->local_port = NULL;

    if (!retval && remote_port)
	retval = actx_copy_addr(context,
				remote_port,
				&auth_context->remote_port);
    else
	auth_context->remote_port = NULL;

    return retval;
}


/*
 * This function overloads the keyblock field. It is only useful prior to
 * a krb5_rd_req_decode() call for user to user authentication where the
 * server has the key and needs to use it to decrypt the incoming request.
 * Once decrypted this key is no longer necessary and is then overwritten
 * with the session key sent by the client.
 */
krb5_error_code KRB5_CALLCONV
krb5_auth_con_setuseruserkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock *keyblock)
{
    if (auth_context->keyblock)
	krb5_free_keyblock(context, auth_context->keyblock);
    return(krb5_copy_keyblock(context, keyblock, &(auth_context->keyblock)));
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock **keyblock)
{
    if (auth_context->keyblock)
    	return krb5_copy_keyblock(context, auth_context->keyblock, keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getlocalsubkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock **keyblock)
{
    return krb5_auth_con_getsendsubkey(context, auth_context, keyblock);
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getremotesubkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock **keyblock)
{
    return krb5_auth_con_getrecvsubkey(context, auth_context, keyblock);
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_setsendsubkey(krb5_context ctx, krb5_auth_context ac, krb5_keyblock *keyblock)
{
    if (ac->send_subkey != NULL)
	krb5_free_keyblock(ctx, ac->send_subkey);
    ac->send_subkey = NULL;
    if (keyblock !=NULL)
	return krb5_copy_keyblock(ctx, keyblock, &ac->send_subkey);
    else
	return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_setrecvsubkey(krb5_context ctx, krb5_auth_context ac, krb5_keyblock *keyblock)
{
    if (ac->recv_subkey != NULL)
	krb5_free_keyblock(ctx, ac->recv_subkey);
    ac->recv_subkey = NULL;
    if (keyblock != NULL)
	return krb5_copy_keyblock(ctx, keyblock, &ac->recv_subkey);
    else
	return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getsendsubkey(krb5_context ctx, krb5_auth_context ac, krb5_keyblock **keyblock)
{
    if (ac->send_subkey != NULL)
	return krb5_copy_keyblock(ctx, ac->send_subkey, keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getrecvsubkey(krb5_context ctx, krb5_auth_context ac, krb5_keyblock **keyblock)
{
    if (ac->recv_subkey != NULL)
	return krb5_copy_keyblock(ctx, ac->recv_subkey, keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_set_req_cksumtype(krb5_context context, krb5_auth_context auth_context, krb5_cksumtype cksumtype)
{
    auth_context->req_cksumtype = cksumtype;
    return 0;
}

krb5_error_code
krb5_auth_con_set_safe_cksumtype(krb5_context context, krb5_auth_context auth_context, krb5_cksumtype cksumtype)
{
    auth_context->safe_cksumtype = cksumtype;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getlocalseqnumber(krb5_context context, krb5_auth_context auth_context, krb5_int32 *seqnumber)
{
    *seqnumber = auth_context->local_seq_number;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getauthenticator(krb5_context context, krb5_auth_context auth_context, krb5_authenticator **authenticator)
{
    return (krb5_copy_authenticator(context, auth_context->authentp,
				    authenticator));
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getremoteseqnumber(krb5_context context, krb5_auth_context auth_context, krb5_int32 *seqnumber)
{
    *seqnumber = auth_context->remote_seq_number;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_initivector(krb5_context context, krb5_auth_context auth_context)
{
    krb5_error_code ret;

    if (auth_context->keyblock) {
	size_t blocksize;

	if ((ret = krb5_c_block_size(context, auth_context->keyblock->enctype,
				    &blocksize)))
	    return(ret);
	if ((auth_context->i_vector = (krb5_pointer)malloc(blocksize))) {
	    memset(auth_context->i_vector, 0, blocksize);
	    return 0;
	}
	return ENOMEM;
    }
    return EINVAL; /* XXX need an error for no keyblock */
}

krb5_error_code
krb5_auth_con_setivector(krb5_context context, krb5_auth_context auth_context, krb5_pointer ivector)
{
    auth_context->i_vector = ivector;
    return 0;
}

krb5_error_code
krb5_auth_con_getivector(krb5_context context, krb5_auth_context auth_context, krb5_pointer *ivector)
{
    *ivector = auth_context->i_vector;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_setflags(krb5_context context, krb5_auth_context auth_context, krb5_int32 flags)
{
    auth_context->auth_context_flags = flags;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_getflags(krb5_context context, krb5_auth_context auth_context, krb5_int32 *flags)
{
    *flags = auth_context->auth_context_flags;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_setrcache(krb5_context context, krb5_auth_context auth_context, krb5_rcache rcache)
{
    auth_context->rcache = rcache;
    return 0;
}
    
krb5_error_code
krb5_auth_con_getrcache(krb5_context context, krb5_auth_context auth_context, krb5_rcache *rcache)
{
    *rcache = auth_context->rcache;
    return 0;
}
    
krb5_error_code
krb5_auth_con_setpermetypes(krb5_context context, krb5_auth_context auth_context, const krb5_enctype *permetypes)
{
    krb5_enctype	* newpe;
    int i;

    for (i=0; permetypes[i]; i++)
	;
    i++; /* include the zero */

    if ((newpe = (krb5_enctype *) malloc(i*sizeof(krb5_enctype)))
	== NULL)
	return(ENOMEM);

    if (auth_context->permitted_etypes)
	krb5_xfree(auth_context->permitted_etypes);

    auth_context->permitted_etypes = newpe;

    memcpy(newpe, permetypes, i*sizeof(krb5_enctype));

    return 0;
}

krb5_error_code
krb5_auth_con_getpermetypes(krb5_context context, krb5_auth_context auth_context, krb5_enctype **permetypes)
{
    krb5_enctype	* newpe;
    int i;

    if (! auth_context->permitted_etypes) {
	*permetypes = NULL;
	return(0);
    }

    for (i=0; auth_context->permitted_etypes[i]; i++)
	;
    i++; /* include the zero */

    if ((newpe = (krb5_enctype *) malloc(i*sizeof(krb5_enctype)))
	== NULL)
	return(ENOMEM);

    *permetypes = newpe;

    memcpy(newpe, auth_context->permitted_etypes, i*sizeof(krb5_enctype));

    return(0);
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_set_checksum_func( krb5_context context,
				 krb5_auth_context  auth_context,
				 krb5_mk_req_checksum_func func,
				 void *data)
{
  auth_context->checksum_func = func;
  auth_context->checksum_func_data = data;
  return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_con_get_checksum_func( krb5_context context,
				 krb5_auth_context auth_context,
				 krb5_mk_req_checksum_func *func,
				 void **data)
{
  *func = auth_context->checksum_func;
  *data = auth_context->checksum_func_data;
  return 0;
}
