/*
 * $Source$
 * $Author$
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
 * krb5_decode_kdc_rep() function.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_decode_kdc_c[] =
"$Id$";
#endif	/* !lint & !SABER */


#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/*
 Takes a KDC_REP message and decrypts encrypted part using etype and
 *key, putting result in *rep.
 dec_rep->client,ticket,session,last_req,server,caddrs
 are all set to allocated storage which should be freed by the caller
 when finished with the response.

 If the response isn't a KDC_REP (tgs or as), it returns an error from
 the decoding routines.

 returns errors from encryption routines, system errors
 */

krb5_error_code
krb5_decode_kdc_rep(DECLARG(krb5_data *, enc_rep),
		    DECLARG(const krb5_keyblock *, key),
		    DECLARG(const krb5_enctype, etype),
		    DECLARG(krb5_kdc_rep **, dec_rep))
OLDDECLARG(krb5_data *, enc_rep)
OLDDECLARG(const krb5_keyblock *, key)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(krb5_kdc_rep **, dec_rep)
{
    krb5_error_code retval;
    krb5_kdc_rep *local_dec_rep;

    if (krb5_is_as_rep(enc_rep))
	retval = decode_krb5_as_rep(enc_rep, &local_dec_rep);
    else if (krb5_is_tgs_rep(enc_rep))
	retval = decode_krb5_tgs_rep(enc_rep, &local_dec_rep);
    else
	return KRB5KRB_AP_ERR_MSG_TYPE;

    if (retval)
	return retval;

    if (local_dec_rep->enc_part.etype != etype) {
	krb5_free_kdc_rep(local_dec_rep);
	return KRB5_WRONG_ETYPE;
    }
    retval = krb5_kdc_rep_decrypt_proc(key, 0, local_dec_rep);
    if (retval) {
	krb5_free_kdc_rep(local_dec_rep);
	return(retval);
    }
    *dec_rep = local_dec_rep;
    return 0;
}

