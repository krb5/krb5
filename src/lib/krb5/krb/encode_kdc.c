/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_encode_kdc_rep() function.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_encode_kdc_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/asn1.h>

#include <errno.h>

#include <krb5/ext-proto.h>

/*
 Takes KDC rep parts in *rep and *encpart, and formats it into *enc_rep,
 using message type type and encryption key client_key and encryption type
 etype.

 The string *enc_rep will be allocated before formatting; the caller should
 free when finished.

 returns system errors

 dec_rep->enc_part is allocated and filled in.
*/
krb5_error_code
krb5_encode_kdc_rep(type, dec_rep, encpart, client_key, enc_rep)
krb5_msgtype type;
register krb5_kdc_rep *dec_rep;
register krb5_enc_kdc_rep_part *encpart;
krb5_keyblock *client_key;
krb5_data **enc_rep;
{
    krb5_data *scratch;
    krb5_encrypt_block eblock;
    krb5_error_code retval;

    if (!valid_etype(dec_rep->etype))
	return KRB5KDC_ERR_ETYPE_NOSUPP;

    switch (type) {
    case KRB5_AS_REP:
    case KRB5_TGS_REP:
	break;
    default:
	return KRB5_BADMSGTYPE;
    }

    if (retval = encode_krb5_enc_kdc_rep_part(encpart, &scratch)) {
	return retval;
    }

#define cleanup_scratch() { (void) bzero(scratch->data, scratch->length); krb5_free_data(scratch); }

    /* put together an eblock for this encryption */

    eblock.crypto_entry = krb5_csarray[dec_rep->etype]->system;
    dec_rep->enc_part.length = krb5_encrypt_size(scratch->length,
					      eblock.crypto_entry);
    if (!(dec_rep->enc_part.data = malloc(dec_rep->enc_part.length))) {
	retval = ENOMEM;
	goto clean_scratch;
    }

#define cleanup_encpart() {(void) bzero(dec_rep->enc_part.data, dec_rep->enc_part.length); free(dec_rep->enc_part.data); dec_rep->enc_part.length = 0; dec_rep->enc_part.data = 0;}

    if (retval = (*eblock.crypto_entry->process_key)(&eblock, client_key)) {
	goto clean_encpart;
    }

#define cleanup_prockey() {(void) (*eblock.crypto_entry->finish_key)(&eblock);}

    if (retval =
	(*eblock.crypto_entry->encrypt_func)((krb5_pointer) scratch->data,
					     (krb5_pointer) dec_rep->enc_part.data,
					     scratch->length, &eblock)) {
	goto clean_prockey;
    }

    /* do some cleanup */
    cleanup_scratch();

    if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
	cleanup_encpart();
	return retval;
    }

    /* now it's ready to be encoded for the wire! */

    switch (type) {
    case KRB5_AS_REP:
	retval = encode_krb5_as_rep(dec_rep, enc_rep);
	break;
    case KRB5_TGS_REP:
	retval = encode_krb5_tgs_rep(dec_rep, enc_rep);
	break;
    }
    if (retval)
	cleanup_encpart();
    return retval;

 clean_prockey:
    cleanup_prockey();
 clean_encpart:
    cleanup_encpart();
 clean_scratch:
    cleanup_scratch();

    return retval;
}
