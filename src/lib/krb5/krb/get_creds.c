/*
 * lib/krb5/krb/get_creds.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_get_credentials()
 */



/*
 Attempts to use the credentials cache or TGS exchange to get an additional
 ticket for the
 client identified by in_creds->client, the server identified by
 in_creds->server, with options options, expiration date specified in
 in_creds->times.endtime (0 means as long as possible), session key type
 specified in in_creds->keyblock.enctype (if non-zero)

 Any returned ticket and intermediate ticket-granting tickets are
 stored in ccache.

 returns errors from encryption routines, system errors
 */

#include "k5-int.h"

static krb5_error_code
krb5_get_credentials_core(context, options, ccache, in_creds, out_creds,
			  mcreds, fields)
    krb5_context context;
    const krb5_flags options;
    krb5_ccache ccache;
    krb5_creds *in_creds;
    krb5_creds **out_creds;
    krb5_creds *mcreds;
    krb5_flags *fields;
{
    if (!in_creds || !in_creds->server || !in_creds->client)
        return EINVAL;

    memset((char *)mcreds, 0, sizeof(krb5_creds));
    mcreds->magic = KV5M_CREDS;
    mcreds->times.endtime = in_creds->times.endtime;
#ifdef HAVE_C_STRUCTURE_ASSIGNMENT
    mcreds->keyblock = in_creds->keyblock;
#else
    memcpy(&mcreds->keyblock, &in_creds->keyblock, sizeof(krb5_keyblock));
#endif
    mcreds->authdata = in_creds->authdata;
    mcreds->server = in_creds->server;
    mcreds->client = in_creds->client;
    
    *fields = KRB5_TC_MATCH_TIMES /*XXX |KRB5_TC_MATCH_SKEY_TYPE */
	| KRB5_TC_MATCH_AUTHDATA
	| KRB5_TC_SUPPORTED_KTYPES;
    if (mcreds->keyblock.enctype)
	*fields |= KRB5_TC_MATCH_KTYPE;
    if (options & KRB5_GC_USER_USER) {
	/* also match on identical 2nd tkt and tkt encrypted in a
	   session key */
	*fields |= KRB5_TC_MATCH_2ND_TKT|KRB5_TC_MATCH_IS_SKEY;
	mcreds->is_skey = TRUE;
	mcreds->second_ticket = in_creds->second_ticket;
	if (!in_creds->second_ticket.length)
	    return KRB5_NO_2ND_TKT;
    }

    return 0;
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_get_credentials(context, options, ccache, in_creds, out_creds)
    krb5_context context;
    const krb5_flags options;
    krb5_ccache ccache;
    krb5_creds FAR *in_creds;
    krb5_creds FAR * FAR *out_creds;
{
    krb5_error_code retval;
    krb5_creds mcreds;
    krb5_creds *ncreds;
    krb5_creds **tgts;
    krb5_flags fields;

    retval = krb5_get_credentials_core(context, options, ccache, 
				       in_creds, out_creds,
				       &mcreds, &fields);

    if (retval) return retval;

    if ((ncreds = (krb5_creds *)malloc(sizeof(krb5_creds))) == NULL)
	return ENOMEM;

    memset((char *)ncreds, 0, sizeof(krb5_creds));
    ncreds->magic = KV5M_CREDS;

    /* The caller is now responsible for cleaning up in_creds */
    if ((retval = krb5_cc_retrieve_cred(context, ccache, fields, &mcreds,
					ncreds))) {
	krb5_xfree(ncreds);
	ncreds = in_creds;
    } else {
	*out_creds = ncreds;
    }

    if ((retval != KRB5_CC_NOTFOUND && retval != KRB5_CC_NOT_KTYPE)
	|| options & KRB5_GC_CACHED)
	return retval;

    retval = krb5_get_cred_from_kdc(context, ccache, ncreds, out_creds, &tgts);
    if (tgts) {
	register int i = 0;
	krb5_error_code rv2;
	while (tgts[i]) {
	    if ((rv2 = krb5_cc_store_cred(context, ccache, tgts[i]))) {
		retval = rv2;
		break;
	    }
	    i++;
	}
	krb5_free_tgt_creds(context, tgts);
    }
    if (!retval)
	retval = krb5_cc_store_cred(context, ccache, *out_creds);
    return retval;
}

#define INT_GC_VALIDATE 1
#define INT_GC_RENEW 2

static krb5_error_code 
krb5_get_credentials_val_renew_core(context, options, ccache, 
				    in_creds, out_creds, which)
    krb5_context context;
    const krb5_flags options;
    krb5_ccache ccache;
    krb5_creds *in_creds;
    krb5_creds **out_creds;
    int which;
{
    krb5_error_code retval;
    krb5_creds mcreds;
    krb5_principal tmp;
    krb5_creds **tgts = 0;
    krb5_flags fields;

    switch(which) {
    case INT_GC_VALIDATE:
	    retval = krb5_get_cred_from_kdc_validate(context, ccache, 
					     in_creds, out_creds, &tgts);
	    break;
    case INT_GC_RENEW:
	    retval = krb5_get_cred_from_kdc_renew(context, ccache, 
					     in_creds, out_creds, &tgts);
	    break;
    default:
	    /* Should never happen */
	    retval = 255;
	    break;
    }
    if (retval) return retval;
    if (tgts) krb5_free_tgt_creds(context, tgts);

    retval = krb5_cc_get_principal(context, ccache, &tmp);
    if (retval) return retval;
    
    retval = krb5_cc_initialize(context, ccache, tmp);
    if (retval) return retval;
    
    retval = krb5_cc_store_cred(context, ccache, *out_creds);
    return retval;
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_get_credentials_validate(context, options, ccache, in_creds, out_creds)
    krb5_context context;
    const krb5_flags options;
    krb5_ccache ccache;
    krb5_creds *in_creds;
    krb5_creds **out_creds;
{
    return(krb5_get_credentials_val_renew_core(context, options, ccache, 
					       in_creds, out_creds, 
					       INT_GC_VALIDATE));
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_get_credentials_renew(context, options, ccache, in_creds, out_creds)
    krb5_context context;
    const krb5_flags options;
    krb5_ccache ccache;
    krb5_creds *in_creds;
    krb5_creds **out_creds;
{

    return(krb5_get_credentials_val_renew_core(context, options, ccache, 
					       in_creds, out_creds, 
					       INT_GC_RENEW));
}

static krb5_error_code
krb5_validate_or_renew_creds(context, creds, client, ccache, in_tkt_service,
			     validate)
     krb5_context context;
     krb5_creds *creds;
     krb5_principal client;
     krb5_ccache ccache;
     char *in_tkt_service;
     int validate;
{
    krb5_error_code ret;
    krb5_creds in_creds; /* only client and server need to be filled in */
    krb5_creds *out_creds = 0; /* for check before dereferencing below */
    krb5_creds **tgts;

    memset((char *)&in_creds, 0, sizeof(krb5_creds));

    in_creds.server = NULL;
    tgts = NULL;

    in_creds.client = client;

    if (in_tkt_service) {
	/* this is ugly, because so are the data structures involved.  I'm
	   in the library, so I'm going to manipulate the data structures
	   directly, otherwise, it will be worse. */

	if (ret = krb5_parse_name(context, in_tkt_service, &in_creds.server))
	    goto cleanup;

	/* stuff the client realm into the server principal.
	   realloc if necessary */
	if (in_creds.server->realm.length < in_creds.client->realm.length)
	    if ((in_creds.server->realm.data =
		 (char *) realloc(in_creds.server->realm.data,
				  in_creds.client->realm.length)) == NULL) {
		ret = ENOMEM;
		goto cleanup;
	    }

	in_creds.server->realm.length = in_creds.client->realm.length;
	memcpy(in_creds.server->realm.data, in_creds.client->realm.data,
	       in_creds.client->realm.length);
    } else {
	if (ret = krb5_build_principal_ext(context, &in_creds.server,
					   in_creds.client->realm.length,
					   in_creds.client->realm.data,
					   KRB5_TGS_NAME_SIZE,
					   KRB5_TGS_NAME,
					   in_creds.client->realm.length,
					   in_creds.client->realm.data,
					   0))
	    goto cleanup;
    }

    if (validate)
	ret = krb5_get_cred_from_kdc_validate(context, ccache, 
					      &in_creds, &out_creds, &tgts);
    else
	ret = krb5_get_cred_from_kdc_renew(context, ccache, 
					   &in_creds, &out_creds, &tgts);
   
    /* ick.  copy the struct contents, free the container */
    if (out_creds) {
	*creds = *out_creds;
	krb5_xfree(out_creds);
    }

cleanup:

    if (in_creds.server)
	krb5_free_principal(context, in_creds.server);
    if (tgts)
	krb5_free_tgt_creds(context, tgts);

    return(ret);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_get_validated_creds(context, creds, client, ccache, in_tkt_service)
     krb5_context context;
     krb5_creds *creds;
     krb5_principal client;
     krb5_ccache ccache;
     char *in_tkt_service;
{
    return(krb5_validate_or_renew_creds(context, creds, client, ccache,
					in_tkt_service, 1));
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_get_renewed_creds(context, creds, client, ccache, in_tkt_service)
     krb5_context context;
     krb5_creds *creds;
     krb5_principal client;
     krb5_ccache ccache;
     char *in_tkt_service;
{
    return(krb5_validate_or_renew_creds(context, creds, client, ccache,
					in_tkt_service, 0));
}
