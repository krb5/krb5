
#include "k5-int.h"
#include "auth_con.h"

krb5_error_code INTERFACE
krb5_auth_con_init(context, auth_context)
    krb5_context      	  context;
    krb5_auth_context  ** auth_context;
{
    if (*auth_context = (krb5_auth_context *)malloc(sizeof(krb5_auth_context))){
	memset(*auth_context, 0, sizeof(krb5_auth_context));

	/* Default flags, do time not seq */
	(*auth_context)->auth_context_flags = 
	  KRB5_AUTH_CONTEXT_DO_TIME |  KRB5_AUTH_CONN_INITIALIZED;

	(*auth_context)->cksumtype = CKSUMTYPE_CRC32;
	return 0;
    }
    return ENOMEM;
}

krb5_error_code INTERFACE
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

krb5_error_code INTERFACE
krb5_auth_con_setaddrs(context, auth_context, local_addr, remote_addr)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_address      	* local_addr;
    krb5_address      	* remote_addr;
{
    auth_context->remote_addr = remote_addr;
    auth_context->local_addr = local_addr;
    return 0;
}

/* XXX this call is a hack. Fixed when I do the servers. */
krb5_error_code INTERFACE
krb5_auth_con_setkey(context, auth_context, keyblock)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_keyblock       * keyblock;		
{
    if (auth_context->keyblock)
	krb5_free_keyblock(context, auth_context->keyblock);
    return(krb5_copy_keyblock(context, keyblock, &(auth_context->keyblock)));
}

krb5_error_code INTERFACE
krb5_auth_con_getlocalsubkey(context, auth_context, keyblock)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_keyblock      ** keyblock;		
{
    return(krb5_copy_keyblock(context, auth_context->local_subkey, keyblock));
}

krb5_error_code INTERFACE
krb5_auth_con_setcksumtype(context, auth_context, cksumtype)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_cksumtype	  cksumtype;		
{
    auth_context->cksumtype = cksumtype;
    return 0;
}

krb5_error_code INTERFACE
krb5_auth_con_getlocalseqnumber(context, auth_context, seqnumber)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_int32	  	* seqnumber;		
{
    *seqnumber = auth_context->local_seq_number;
    return 0;
}

krb5_error_code INTERFACE
krb5_auth_con_setivector(context, auth_context, ivector)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_pointer	  ivector;
{
    auth_context->i_vector = ivector;
    return 0;
}

krb5_error_code INTERFACE
krb5_auth_con_getivector(context, auth_context, ivector)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_pointer	* ivector;
{
    *ivector = auth_context->i_vector;
    return 0;
}

krb5_error_code INTERFACE
krb5_auth_con_setflags(context, auth_context, flags)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_int32		  flags;
{
    auth_context->auth_context_flags = flags;
    return 0;
}

krb5_error_code INTERFACE
krb5_auth_con_setrcache(context, auth_context, rcache)
    krb5_context      	  context;
    krb5_auth_context 	* auth_context;
    krb5_rcache		  rcache;
{
    auth_context->rcache = rcache;
    return 0;
}

