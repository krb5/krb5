
#include "k5-int.h"
#include "auth_con.h"

krb5_error_code
krb5_auth_con_init(context, auth_context)
    krb5_context      	  context;
    krb5_auth_context  ** auth_context;
{
    if (*auth_context = (krb5_auth_context *)malloc(sizeof(krb5_auth_context))){
	memset(*auth_context, 0, sizeof(krb5_auth_context));

	/* Default flags, do time not seq */
	(*auth_context)->auth_context_flags = 
	  KRB5_AUTH_CONTEXT_DO_TIME |  KRB5_AUTH_CONN_INITIALIZED;

	(*auth_context)->cksumtype = CKSUMTYPE_RSA_MD4_DES;
	/* (*auth_context)->cksumtype = CKSUMTYPE_CRC32; */
	return 0;
    }
    return ENOMEM;
}

krb5_error_code
krb5_auth_con_free(context, auth_context)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
{
    if (auth_context->authentp) 
	krb5_free_authenticator(context, auth_context->authentp);
    if (auth_context->keyblock) 
	krb5_free_keyblock(context, auth_context->keyblock);
    if (auth_context->local_subkey) 
	krb5_free_keyblock(context, auth_context->local_subkey);
    if (auth_context->remote_subkey) 
	krb5_free_keyblock(context, auth_context->remote_subkey);
    free(auth_context);
    return 0;
}

krb5_error_code
krb5_auth_con_setaddrs(context, auth_context, local_addr, remote_addr)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_address      	* local_addr;
    krb5_address      	* remote_addr;
{
    /* Free old addresses */
    if (auth_context->local_addr) 
	free(auth_context->local_addr);
    if (auth_context->remote_addr) 
	free(auth_context->remote_addr);

    if (local_addr) {
	if ((auth_context->local_addr = (krb5_address *)
		malloc(sizeof(krb5_address) + local_addr->length)) == NULL) {
	    return ENOMEM;
	}
	auth_context->local_addr->addrtype = local_addr->addrtype;
	auth_context->local_addr->length = local_addr->length;
	auth_context->local_addr->contents = (krb5_octet *)
	  auth_context->local_addr + sizeof(krb5_address);
	memcpy(auth_context->local_addr->contents,
	       local_addr->contents, local_addr->length);
    } else {
	auth_context->local_addr = NULL;
    }

    if (remote_addr) {
	if ((auth_context->remote_addr = (krb5_address *)
		malloc(sizeof(krb5_address) + remote_addr->length)) == NULL) {
	    if (auth_context->local_addr)
		free(auth_context->local_addr);
	    return ENOMEM;
	}
	auth_context->remote_addr->addrtype = remote_addr->addrtype;
	auth_context->remote_addr->length = remote_addr->length;
	auth_context->remote_addr->contents = (krb5_octet *)
	  auth_context->remote_addr + sizeof(krb5_address);
	memcpy(auth_context->remote_addr->contents,
	       remote_addr->contents, remote_addr->length);
    } else {
	auth_context->remote_addr = NULL;
    }
    return 0;
}

/* XXX this call is a hack. Fixed when I do the servers. */
krb5_error_code
krb5_auth_con_setkey(context, auth_context, keyblock)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_keyblock       * keyblock;		
{
    if (auth_context->keyblock)
	krb5_free_keyblock(context, auth_context->keyblock);
    return(krb5_copy_keyblock(context, keyblock, &(auth_context->keyblock)));
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
    krb5_auth_context 	* auth_context;
    krb5_keyblock       * keyblock;		
{
    if (auth_context->keyblock)
	krb5_free_keyblock(context, auth_context->keyblock);
    return(krb5_copy_keyblock(context, keyblock, &(auth_context->keyblock)));
}

krb5_error_code
krb5_auth_con_getkey(context, auth_context, keyblock)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
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
    krb5_auth_context 	* auth_context;
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
    krb5_auth_context 	* auth_context;
    krb5_keyblock      ** keyblock;		
{
    if (auth_context->remote_subkey)
    	return krb5_copy_keyblock(context,auth_context->remote_subkey,keyblock);
    *keyblock = NULL;
    return 0;
}

krb5_error_code
krb5_auth_con_setcksumtype(context, auth_context, cksumtype)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_cksumtype	  cksumtype;		
{
    auth_context->cksumtype = cksumtype;
    return 0;
}

krb5_error_code
krb5_auth_con_getlocalseqnumber(context, auth_context, seqnumber)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_int32	  	* seqnumber;		
{
    *seqnumber = auth_context->local_seq_number;
    return 0;
}

krb5_error_code
krb5_auth_con_getauthenticator(context, auth_context, authenticator)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_authenticator ** authenticator;		
{
    return (krb5_copy_authenticator(context, auth_context->authentp,
				    authenticator));
}

krb5_error_code
krb5_auth_con_getremoteseqnumber(context, auth_context, seqnumber)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_int32	  	* seqnumber;		
{
    *seqnumber = auth_context->remote_seq_number;
    return 0;
}

krb5_error_code
krb5_auth_con_initivector(context, auth_context)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
{
    if (auth_context->keyblock) {
	int size = krb5_keytype_array[auth_context->keyblock->keytype]->
		      system->block_length;

	if (auth_context->i_vector = (krb5_pointer)malloc(size)) {
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
    krb5_auth_context 	* auth_context;
    krb5_pointer	  ivector;
{
    auth_context->i_vector = ivector;
    return 0;
}

krb5_error_code
krb5_auth_con_getivector(context, auth_context, ivector)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_pointer	* ivector;
{
    *ivector = auth_context->i_vector;
    return 0;
}

krb5_error_code
krb5_auth_con_setflags(context, auth_context, flags)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_int32		  flags;
{
    auth_context->auth_context_flags = flags;
    return 0;
}

krb5_error_code
krb5_auth_con_setrcache(context, auth_context, rcache)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_rcache		  rcache;
{
    auth_context->rcache = rcache;
    return 0;
}

