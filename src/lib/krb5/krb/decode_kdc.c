/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_decode_kdc_rep() function.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_decode_kdc_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/isode_err.h>
#include <krb5/asn1.h>

#include <errno.h>

#include <krb5/ext-proto.h>

/*
 Takes a KDC_REP message and decrypts encrypted part using etype and
 *key, putting result in *rep.
 dec_rep->client,ticket,session.last_req,server,caddrs
 are all set to allocated storage which should be freed by the caller
 when finished with the response.

 If the response isn't a KDC_REP (tgs or as), it returns an error from
 the decoding routines (usually ISODE_50_LOCAL_ERR_BADDECODE).

 returns errors from encryption routines, system errors
 */

krb5_error_code
krb5_decode_kdc_rep(enc_rep, key, etype, dec_rep)
krb5_data *enc_rep;
krb5_keyblock *key;
krb5_enctype etype;
krb5_kdc_rep **dec_rep;
{
    krb5_error_code retval;
    krb5_kdc_rep *local_dec_rep;


    /* XXX maybe caller should specify type expected? */
    retval = decode_krb5_as_rep(enc_rep, &local_dec_rep);
    switch (retval) {
    case ISODE_50_LOCAL_ERR_BADMSGTYPE:
	retval = decode_krb5_tgs_rep(enc_rep, &local_dec_rep);
	switch (retval) {
	case 0:
	    break;
	default:
	    return(retval);
	}
    case 0:
	break;
    default:
	return (retval);
    }

    if (local_dec_rep->etype != etype) {
	return KRB5KDC_ERR_ETYPE_NOSUPP; /* XXX */
    }
    if (retval = krb5_kdc_rep_decrypt_proc(local_dec_rep, key, 0)) {
	krb5_free_kdc_rep(local_dec_rep);
	return(retval);
    }
    *dec_rep = local_dec_rep;
    return 0;
}

