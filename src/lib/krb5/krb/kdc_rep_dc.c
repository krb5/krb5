/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_kdc_rep_decrypt_proc()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdc_rep_dc_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/ext-proto.h>

/*
 * Decrypt the encrypted portion of the KDC_REP message, using the key
 * passed.
 *
 */

/*ARGSUSED*/
krb5_error_code
krb5_kdc_rep_decrypt_proc(DECLARG(const krb5_keyblock *, key),
			  DECLARG(const krb5_pointer, decryptarg),
			  DECLARG(krb5_kdc_rep *, dec_rep))
OLDDECLARG(const krb5_keyblock *, key)
OLDDECLARG(const krb5_pointer, decryptarg)
OLDDECLARG(krb5_kdc_rep *, dec_rep)
{
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    krb5_data scratch;
    krb5_enc_kdc_rep_part *local_encpart;

    if (!valid_etype(dec_rep->etype))
	return KRB5_PROG_ETYPE_NOSUPP;

    /* set up scratch decrypt/decode area */

    scratch.length = dec_rep->enc_part.length;
    if (!(scratch.data = malloc(dec_rep->enc_part.length))) {
	return(ENOMEM);
    }

    /* put together an eblock for this encryption */

    eblock.crypto_entry = krb5_csarray[dec_rep->etype]->system;

    /* do any necessary key pre-processing */
    if (retval = (*eblock.crypto_entry->process_key)(&eblock, key)) {
	free(scratch.data);
	return(retval);
    }

    /* call the decryption routine */
    if (retval =
	(*eblock.crypto_entry->decrypt_func)((krb5_pointer) dec_rep->enc_part.data,
					     (krb5_pointer) scratch.data,
					     scratch.length, &eblock, 0)) {
	(void) (*eblock.crypto_entry->finish_key)(&eblock);
	free(scratch.data);
	return retval;
    }
#define clean_scratch() {bzero(scratch.data, scratch.length); free(scratch.data);}
    if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
	clean_scratch();
	return retval;
    }

    /* and do the decode */
    retval = decode_krb5_enc_kdc_rep_part(&scratch, &local_encpart);
    clean_scratch();
    if (retval)
	return retval;

    dec_rep->enc_part2 = local_encpart;

    return 0;
}
