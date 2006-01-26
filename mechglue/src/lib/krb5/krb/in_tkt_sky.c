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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * krb5_get_in_tkt_with_skey()
 *	
 */

#include "k5-int.h"

struct skey_keyproc_arg {
    const krb5_keyblock *key;
    krb5_principal client;		/* it's a pointer, really! */
};

/*
 * Key-generator for in_tkt_skey, below.
 * "keyseed" is actually a krb5_keyblock *, or NULL if we should fetch
 * from system area.
 */
static krb5_error_code skey_keyproc
    (krb5_context,
               const krb5_enctype,
               krb5_data *,
               krb5_const_pointer,
               krb5_keyblock **);

static krb5_error_code
skey_keyproc(krb5_context context, krb5_enctype type, krb5_data *salt,
	     krb5_const_pointer keyseed, krb5_keyblock **key)
{
    krb5_keyblock *realkey;
    krb5_error_code retval;
    const krb5_keyblock * keyblock;

    keyblock = (const krb5_keyblock *)keyseed;

    if (!krb5_c_valid_enctype(type))
	return KRB5_PROG_ETYPE_NOSUPP;

    if ((retval = krb5_copy_keyblock(context, keyblock, &realkey)))
	return retval;
	
    if (realkey->enctype != type) {
	krb5_free_keyblock(context, realkey);
	return KRB5_PROG_ETYPE_NOSUPP;
    }	

    *key = realkey;
    return 0;
}

/*
 Similar to krb5_get_in_tkt_with_password.

 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, and using creds->times.starttime, creds->times.endtime,
 creds->times.renew_till as from, till, and rtime.  
 creds->times.renew_till is ignored unless the RENEWABLE option is requested.

 If addrs is non-NULL, it is used for the addresses requested.  If it is
 null, the system standard addresses are used.

 If keyblock is NULL, an appropriate key for creds->client is retrieved
 from the system key store (e.g. /etc/srvtab).  If keyblock is non-NULL,
 it is used as the decryption key.

 A succesful call will place the ticket in the credentials cache ccache.

 returns system errors, encryption errors

 */
krb5_error_code KRB5_CALLCONV
krb5_get_in_tkt_with_skey(krb5_context context, krb5_flags options,
			  krb5_address *const *addrs, krb5_enctype *ktypes,
			  krb5_preauthtype *pre_auth_types,
			  const krb5_keyblock *key, krb5_ccache ccache,
			  krb5_creds *creds, krb5_kdc_rep **ret_as_reply)
{
    if (key) 
    	return krb5_get_in_tkt(context, options, addrs, ktypes, pre_auth_types, 
			       skey_keyproc, (krb5_const_pointer)key,
			       krb5_kdc_rep_decrypt_proc, 0, creds,
			       ccache, ret_as_reply);
    else 
	return krb5_get_in_tkt_with_keytab(context, options, addrs, ktypes,
					   pre_auth_types, NULL, ccache,
					   creds, ret_as_reply);
}
