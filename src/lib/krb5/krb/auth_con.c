
#include "k5-int.h"
#include "auth_con.h"

static krb5_error_code
actx_copy_addr(context, inad, outad)
    krb5_context	context;
    const krb5_address	*inad;
    krb5_address	**outad;
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

krb5_error_code
krb5_auth_con_init(context, auth_context)
    krb5_context      	  context;
    krb5_auth_context  * auth_context;
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
    (*auth_context)->magic = KV5M_AUTH_CONTEXT;
    return 0;
}

krb5_error_code
krb5_auth_con_free(context, auth_context)
    krb5_context      	  context;
    krb5_auth_context     auth_context;
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
    if (auth_context->local_subkey) 
	krb5_free_keyblock(context, auth_context->local_subkey);
    if (auth_context->remote_subkey) 
	krb5_free_keyblock(context, auth_context->remote_subkey);
    if (auth_context->rcache)
	krb5_rc_close(context, auth_context->rcache);
    free(auth_context);
    return 0;
}

krb5_error_code
krb5_auth_con_setaddrs(context, auth_context, local_addr, remote_addr)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_address      	* local_addr;
    krb5_address      	* remote_addr;
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

krb5_error_code
krb5_auth_con_getaddrs(context, auth_context, local_addr, remote_addr)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_address       ** local_addr;
    krb5_address       ** remote_addr;
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

krb5_error_code
krb5_auth_con_setports(context, auth_context, local_port, remote_port)
    krb5_context      	  context;
    krb5_auth_context     auth_context;
    krb5_address      	* local_port;
    krb5_address      	* remote_port;
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
krb5_error_code
krb5_auth_con_setuseruserkey(context, auth_context, keyblock)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_keyblock       * keyblock;		
{
    if (auth_context->keyblock)
	krb5_free_keyblock(context, auth_context->keyblock);
    return(krb5_copy_keyblock(context, keyblock, &(auth_context->keyblock)));
}

krb5_error_code
krb5_auth_con_getkey(context, auth_context, keyblock)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_keyblock      ** keyblock;		
{
    if (auth_context->keyblock)
    	return krb5_copy_keyblock(context, auth_context->keyblock, keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code
krb5_auth_con_getlocalsubkey(context, auth_context, keyblock)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_keyblock      ** keyblock;		
{
    if (auth_context->local_subkey)
    	return krb5_copy_keyblock(context,auth_context->local_subkey,keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code
krb5_auth_con_getremotesubkey(context, auth_context, keyblock)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_keyblock      ** keyblock;		
{
    if (auth_context->remote_subkey)
    	return krb5_copy_keyblock(context,auth_context->remote_subkey,keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code
krb5_auth_con_set_req_cksumtype(context, auth_context, cksumtype)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_cksumtype	  cksumtype;		
{
    auth_context->req_cksumtype = cksumtype;
    return 0;
}

krb5_error_code
krb5_auth_con_set_safe_cksumtype(context, auth_context, cksumtype)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_cksumtype	  cksumtype;		
{
    auth_context->safe_cksumtype = cksumtype;
    return 0;
}

krb5_error_code
krb5_auth_con_getlocalseqnumber(context, auth_context, seqnumber)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_int32	  	* seqnumber;		
{
    *seqnumber = auth_context->local_seq_number;
    return 0;
}

krb5_error_code
krb5_auth_con_getauthenticator(context, auth_context, authenticator)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_authenticator ** authenticator;		
{
    return (krb5_copy_authenticator(context, auth_context->authentp,
				    authenticator));
}

krb5_error_code
krb5_auth_con_getremoteseqnumber(context, auth_context, seqnumber)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_int32	  	* seqnumber;		
{
    *seqnumber = auth_context->remote_seq_number;
    return 0;
}

krb5_error_code
krb5_auth_con_initivector(context, auth_context)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
{
    if (auth_context->keyblock) {
	int size = krb5_enctype_array[auth_context->keyblock->enctype]->
		      system->block_length;

	if ((auth_context->i_vector = (krb5_pointer)malloc(size))) {
	    memset(auth_context->i_vector, 0, size);
	    return 0;
	}
	return ENOMEM;
    }
    return EINVAL; /* XXX need an error for no keyblock */
}

krb5_error_code
krb5_auth_con_setivector(context, auth_context, ivector)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_pointer	  ivector;
{
    auth_context->i_vector = ivector;
    return 0;
}

krb5_error_code
krb5_auth_con_getivector(context, auth_context, ivector)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_pointer	* ivector;
{
    *ivector = auth_context->i_vector;
    return 0;
}

krb5_error_code
krb5_auth_con_setflags(context, auth_context, flags)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_int32		  flags;
{
    auth_context->auth_context_flags = flags;
    return 0;
}

krb5_error_code
krb5_auth_con_getflags(context, auth_context, flags)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_int32		* flags;
{
    *flags = auth_context->auth_context_flags;
    return 0;
}

krb5_error_code
krb5_auth_con_setrcache(context, auth_context, rcache)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_rcache		  rcache;
{
    auth_context->rcache = rcache;
    return 0;
}
    
krb5_error_code
krb5_auth_con_getrcache(context, auth_context, rcache)
    krb5_context      	  context;
    krb5_auth_context 	  auth_context;
    krb5_rcache		* rcache;
{
    *rcache = auth_context->rcache;
    return 0;
}
    
