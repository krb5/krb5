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
    krb5_encrypt_block eblock;
    krb5_data scratch;
    krb5_enc_kdc_rep_part *local_encpart;


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
    scratch.length = local_dec_rep->enc_part.length;
    if (!(scratch.data = malloc(local_dec_rep->enc_part.length))) {
	krb5_free_kdc_rep(local_dec_rep);
	return(ENOMEM);
    }

    if (!valid_etype(etype))
	return KRB5KDC_ERR_ETYPE_NOSUPP;

    /* put together an eblock for this encryption */

    eblock.crypto_entry = krb5_csarray[etype]->system;

    /* do any necessary key pre-processing */
    if (retval = (*eblock.crypto_entry->process_key)(&eblock, key)) {
	krb5_free_kdc_rep(local_dec_rep);
	free(scratch.data);
	return(retval);
    }

    /* call the encryption routine */
    if (retval =
	(*eblock.crypto_entry->decrypt_func)((krb5_pointer) local_dec_rep->enc_part.data,
					     (krb5_pointer) scratch.data,
					     scratch.length, &eblock)) {
	(void) (*eblock.crypto_entry->finish_key)(&eblock);
	krb5_free_kdc_rep(local_dec_rep);
	free(scratch.data);
	return retval;
    }
#define clean_scratch() {bzero(scratch.data, scratch.length); free(scratch.data);}
    if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
	krb5_free_kdc_rep(local_dec_rep);
	clean_scratch();
	return retval;
    }
    if (retval = decode_krb5_enc_kdc_rep_part(&scratch, &local_encpart)) {
	krb5_free_kdc_rep(local_dec_rep);
	clean_scratch();
	return retval;
    }
    clean_scratch();

    local_dec_rep->enc_part2 = local_encpart;
    *dec_rep = local_dec_rep;
    return 0;
}

