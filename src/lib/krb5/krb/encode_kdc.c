/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_encode_kdc_rep() function.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_encode_kdc_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>

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
/* due to promotion rules, we need to play with this... */
krb5_error_code
krb5_encode_kdc_rep(DECLARG(const krb5_msgtype, type),
		    DECLARG(const register krb5_enc_kdc_rep_part *, encpart),
		    DECLARG(const krb5_keyblock *, client_key),
		    DECLARG(register krb5_kdc_rep *, dec_rep),
		    DECLARG(krb5_data **, enc_rep))
OLDDECLARG(const krb5_msgtype, type)
OLDDECLARG(const register krb5_enc_kdc_rep_part *, encpart)
OLDDECLARG(const krb5_keyblock *, client_key)
OLDDECLARG(register krb5_kdc_rep *, dec_rep)
OLDDECLARG(krb5_data **, enc_rep)
{
    krb5_data *scratch;
    krb5_encrypt_block eblock;
    krb5_error_code retval;

    if (!valid_etype(dec_rep->etype))
	return KRB5_PROG_ETYPE_NOSUPP;

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
    /* add padding area, and zero it */
    if (!(scratch->data = realloc(scratch->data, dec_rep->enc_part.length))) {
	/* may destroy scratch->data */
	xfree(scratch);
	return ENOMEM;
    }
    bzero(scratch->data + scratch->length,
	  dec_rep->enc_part.length - scratch->length);
    if (!(dec_rep->enc_part.data = malloc(dec_rep->enc_part.length))) {
	retval = ENOMEM;
	goto clean_scratch;
    }

#define cleanup_encpart() {(void) bzero(dec_rep->enc_part.data, dec_rep->enc_part.length); free(dec_rep->enc_part.data); dec_rep->enc_part.length = 0; dec_rep->enc_part.data = 0;}

    if (retval = krb5_process_key(&eblock, client_key)) {
	goto clean_encpart;
    }

#define cleanup_prockey() {(void) krb5_finish_key(&eblock);}

    if (retval = krb5_encrypt((krb5_pointer) scratch->data,
			      (krb5_pointer) dec_rep->enc_part.data,
			      scratch->length, &eblock, 0)) {
	goto clean_prockey;
    }

    /* do some cleanup */
    cleanup_scratch();

    if (retval = krb5_finish_key(&eblock)) {
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
