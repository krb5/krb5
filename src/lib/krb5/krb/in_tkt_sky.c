/*
 * lib/krb5/krb/in_tkt_sky.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * krb5_get_in_tkt_with_skey()
 *	
 */


#include <krb5/krb5.h>

#include <krb5/ext-proto.h>

struct skey_keyproc_arg {
    const krb5_keyblock *key;
    krb5_principal client;		/* it's a pointer, really! */
};

/*
 * Key-generator for in_tkt_skey, below.
 * "keyseed" is actually a krb5_keyblock *, or NULL if we should fetch
 * from system area.
 */
#include <krb5/widen.h>
static krb5_error_code
skey_keyproc(DECLARG(const krb5_keytype, type),
	     DECLARG(krb5_keyblock **, key),
	     DECLARG(krb5_const_pointer, keyseed),
	     DECLARG(krb5_pa_data **, padata))
OLDDECLARG(const krb5_keytype, type)
OLDDECLARG(krb5_keyblock **, key)
OLDDECLARG(krb5_const_pointer, keyseed)
OLDDECLARG(krb5_pa_data **,padata)
#include <krb5/narrow.h>
{
    krb5_keyblock *realkey;
    const struct skey_keyproc_arg *arg;
    krb5_error_code retval;
    krb5_keytab kt_id;
    krb5_keytab_entry kt_ent;

    arg = (const struct skey_keyproc_arg *)keyseed;

    if (!valid_keytype(type))
	return KRB5_PROG_ETYPE_NOSUPP;

    if (arg->client) {
	/* do keytab stuff */
	/* else we need to fetch from system key place */
	if (retval = krb5_kt_default(&kt_id))
	    return retval;
	if (retval = krb5_kt_get_entry(kt_id, arg->client,
				       0, /* don't have vno available */
				       &kt_ent))
	    return retval;
    }
#define cleanup() {if (arg->client) (void) krb5_kt_free_entry(&kt_ent);}

    if (arg->key)
	retval = krb5_copy_keyblock(arg->key, &realkey);
    else
	retval = krb5_copy_keyblock(&kt_ent.key, &realkey);
    if (retval) {
	cleanup();
	return retval;
    }
	
    if (realkey->keytype != type) {
	krb5_free_keyblock(realkey);
	cleanup();
	return KRB5_PROG_ETYPE_NOSUPP;
    }	

    *key = realkey;
    cleanup();
    return 0;
}

/*
 Similar to krb5_get_in_tkt_with_password.

 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, requesting encryption type etype, and using
 creds->times.starttime,  creds->times.endtime,  creds->times.renew_till
 as from, till, and rtime.  creds->times.renew_till is ignored unless
 the RENEWABLE option is requested.

 If addrs is non-NULL, it is used for the addresses requested.  If it is
 null, the system standard addresses are used.

 If keyblock is NULL, an appropriate key for creds->client is retrieved
 from the system key store (e.g. /etc/srvtab).  If keyblock is non-NULL,
 it is used as the decryption key.

 A succesful call will place the ticket in the credentials cache ccache.

 returns system errors, encryption errors

 */
krb5_error_code
krb5_get_in_tkt_with_skey(DECLARG(const krb5_flags, options),
			  DECLARG(krb5_address * const *, addrs),
			  DECLARG(const krb5_preauthtype, pre_auth_type),
			  DECLARG(const krb5_enctype, etype),
			  DECLARG(const krb5_keyblock *,key),
			  DECLARG(krb5_ccache, ccache),
			  DECLARG(krb5_creds *,creds),
			  DECLARG(krb5_kdc_rep **, ret_as_reply))
OLDDECLARG(const krb5_flags, options)
OLDDECLARG(krb5_address * const *, addrs)
OLDDECLARG(const krb5_preauthtype, pre_auth_type)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_keyblock *,key)
OLDDECLARG(krb5_ccache, ccache)
OLDDECLARG(krb5_creds *, creds)
OLDDECLARG(krb5_kdc_rep **, ret_as_reply)

{
    struct skey_keyproc_arg arg;
    krb5_keytype keytype;

    if (key) {
	arg.key = key;
	arg.client = 0;
	keytype = key->keytype;
    } else {
	arg.key = 0;
	arg.client = creds->client;
	if (!valid_etype(etype))
	    return(KRB5_PROG_ETYPE_NOSUPP);

	keytype = krb5_csarray[etype]->system->proto_keytype;
    }
    return (krb5_get_in_tkt(options, addrs, pre_auth_type, etype, keytype,
			    skey_keyproc, (krb5_pointer) &arg,
			    krb5_kdc_rep_decrypt_proc, 0, creds,
			    ccache, ret_as_reply));
}
