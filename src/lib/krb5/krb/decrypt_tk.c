/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_decrypt_tkt_part() function.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_decrypt_tk_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include <krb5/ext-proto.h>

/*
 Decrypts dec_ticket->enc_part
 using *srv_key, and places result in dec_ticket->enc_part2.
 The storage of dec_ticket->enc_part2 will be allocated before return.

 returns errors from encryption routines, system errors

*/

krb5_error_code
krb5_decrypt_tkt_part(srv_key, ticket)
const krb5_keyblock *srv_key;
register krb5_ticket *ticket;
{
    krb5_enc_tkt_part *dec_tkt_part;
    krb5_encrypt_block eblock;
    krb5_data scratch;
    krb5_error_code retval;

    if (!valid_etype(ticket->enc_part.etype))
	return KRB5_PROG_ETYPE_NOSUPP;

    /* put together an eblock for this encryption */

    eblock.crypto_entry = krb5_csarray[ticket->enc_part.etype]->system;

    scratch.length = ticket->enc_part.ciphertext.length;
    if (!(scratch.data = malloc(ticket->enc_part.ciphertext.length)))
	return(ENOMEM);

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(&eblock, srv_key)) {
	free(scratch.data);
	return(retval);
    }

    /* call the encryption routine */
    if (retval = krb5_decrypt((krb5_pointer) ticket->enc_part.ciphertext.data,
			      (krb5_pointer) scratch.data,
			      scratch.length, &eblock, 0)) {
	(void) krb5_finish_key(&eblock);
	free(scratch.data);
	return retval;
    }
#define clean_scratch() {bzero(scratch.data, scratch.length); free(scratch.data);}
    if (retval = krb5_finish_key(&eblock)) {

	clean_scratch();
	return retval;
    }
    /*  now decode the decrypted stuff */
    if (!(retval = decode_krb5_enc_tkt_part(&scratch, &dec_tkt_part))) {
	ticket->enc_part2 = dec_tkt_part;
    }
    clean_scratch();
    return retval;
}
