/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_encrypt_tkt_part() routine.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_encrypt_tk_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include <errno.h>

#include <krb5/ext-proto.h>

/* array of pointers into encryption systems */
extern krb5_cs_table_entry *csarray[];

/*
 Takes unencrypted dec_ticket & dec_tkt_part, encrypts with dec_ticket->etype
 using *srv_key, and places result in dec_ticket->enc_part.
 The string dec_ticket->enc_part will be allocated  before formatting.

 returns errors from encryption routines, system errors

 enc_part->data allocated & filled in with encrypted stuff
*/

krb5_error_code
krb5_encrypt_tkt_part(dec_tkt_part, srv_key, dec_ticket)
register krb5_enc_tkt_part *dec_tkt_part;
krb5_keyblock *srv_key;
register krb5_ticket *dec_ticket;
{
    krb5_data *scratch;
    krb5_error_code retval;
    krb5_encrypt_block eblock;

    /* encrypt the encrypted part */

    /*  start by encoding the to-be-encrypted part. */
    if (retval = encode_krb5_enc_tkt_part(dec_tkt_part, &scratch)) {
	return retval;
    }

#define cleanup_scratch() { (void) bzero(scratch->data, scratch->length); krb5_free_data(scratch); }

    /* put together an eblock for this encryption */

    eblock.crypto_entry = csarray[dec_ticket->etype]->system;
    dec_ticket->enc_part.length = krb5_encrypt_size(scratch->length,
						     eblock.crypto_entry);
    if (!(dec_ticket->enc_part.data = malloc(dec_ticket->enc_part.length))) {
	retval = ENOMEM;
	goto clean_scratch;
    }

#define cleanup_encpart() {(void) bzero(dec_ticket->enc_part.data, dec_ticket->enc_part.length); free(dec_ticket->enc_part.data); dec_ticket->enc_part.length = 0; dec_ticket->enc_part.data = 0;}

    /* do any necessary key pre-processing */
    if (retval = (*eblock.crypto_entry->process_key)(&eblock, srv_key)) {
	goto clean_encpart;
    }

#define cleanup_prockey() {(void) (*eblock.crypto_entry->finish_key)(&eblock);}

    /* call the encryption routine */
    if (retval =
	(*eblock.crypto_entry->encrypt_func)((krb5_pointer) scratch->data,
					     (krb5_pointer) dec_ticket->enc_part.data,
					     scratch->length, &eblock)) {
	goto clean_prockey;
    }

    /* ticket is now assembled-- do some cleanup */
    cleanup_scratch();

    if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
	cleanup_encpart();
	return retval;
    }

    return 0;

 clean_prockey:
    cleanup_prockey();
 clean_encpart:
    cleanup_encpart();
 clean_scratch:
    cleanup_scratch();

    return retval;
}
