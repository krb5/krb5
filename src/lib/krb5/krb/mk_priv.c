/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_mk_priv()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mk_priv_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>

/*
 Formats a KRB_PRIV message into outbuf.

 userdata is formatted as the user data in the message.
 etype specifies the encryption type; key specifies the key for the
 encryption; sender_addr and recv_addr specify the full addresses (host
 and port) of the sender and receiver.

 i_vector is used as an initialization vector for the encryption, and if
 non-NULL its contents are replaced with the last block of the encrypted
 data upon exit.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 returns system errors
*/
krb5_error_code
krb5_mk_priv(DECLARG(const krb5_data *, userdata),
	     DECLARG(const krb5_enctype, etype),
	     DECLARG(const krb5_keyblock *, key),
	     DECLARG(const krb5_fulladdr *, sender_addr),
	     DECLARG(const krb5_fulladdr *, recv_addr),
	     DECLARG(krb5_pointer, i_vector),
	     DECLARG(krb5_data *, outbuf))
OLDDECLARG(const krb5_data *, userdata)
OLDDECLARG(const krb5_enctype, etype)
OLDDECLARG(const krb5_keyblock *, key)
OLDDECLARG(const krb5_fulladdr *, sender_addr)
OLDDECLARG(const krb5_fulladdr *, recv_addr)
OLDDECLARG(krb5_pointer, i_vector)
OLDDECLARG(krb5_data *, outbuf)
{
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    krb5_priv privmsg;
    krb5_priv_enc_part privmsg_enc_part;
    krb5_data *scratch;

    if (!valid_etype(etype))
	return KRB5_PROG_ETYPE_NOSUPP;
    privmsg.enc_part.etype = etype; 
    privmsg.enc_part.kvno = 0;	/* XXX allow user-set? */

    privmsg_enc_part.user_data = *userdata;
    privmsg_enc_part.s_address = sender_addr->address;
    privmsg_enc_part.r_address = recv_addr->address;

    if (retval = krb5_ms_timeofday(&privmsg_enc_part.timestamp,
				   &privmsg_enc_part.msec))
	return retval;

    if (krb5_fulladdr_order(sender_addr, recv_addr) > 0)
	privmsg_enc_part.msec =
	    (privmsg_enc_part.msec & MSEC_VAL_MASK) | MSEC_DIRBIT;
    else
	/* this should be a no-op, but just to be sure... */
	privmsg_enc_part.msec = privmsg_enc_part.msec & MSEC_VAL_MASK;

    /* start by encoding to-be-encrypted part of the message */

    if (retval = encode_krb5_enc_priv_part(&privmsg_enc_part, &scratch))
	return retval;

#define cleanup_scratch() { (void) memset(scratch->data, 0, scratch->length); krb5_free_data(scratch); }

    /* put together an eblock for this encryption */

    eblock.crypto_entry = krb5_csarray[etype]->system;
    privmsg.enc_part.ciphertext.length = krb5_encrypt_size(scratch->length,
						eblock.crypto_entry);
    /* add padding area, and zero it */
    if (!(scratch->data = realloc(scratch->data,
				  privmsg.enc_part.ciphertext.length))) {
	/* may destroy scratch->data */
	xfree(scratch);
	return ENOMEM;
    }
    memset(scratch->data + scratch->length, 0,
	  privmsg.enc_part.ciphertext.length - scratch->length);
    if (!(privmsg.enc_part.ciphertext.data =
	  malloc(privmsg.enc_part.ciphertext.length))) {
        retval = ENOMEM;
        goto clean_scratch;
    }

#define cleanup_encpart() {\
(void) memset(privmsg.enc_part.ciphertext.data, 0, \
	     privmsg.enc_part.ciphertext.length); \
free(privmsg.enc_part.ciphertext.data); \
privmsg.enc_part.ciphertext.length = 0; privmsg.enc_part.ciphertext.data = 0;}

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(&eblock, key)) {
        goto clean_encpart;
    }

#define cleanup_prockey() {(void) krb5_finish_key(&eblock);}

    /* call the encryption routine */
    if (retval = krb5_encrypt((krb5_pointer) scratch->data,
			      (krb5_pointer) privmsg.enc_part.ciphertext.data,
			      scratch->length, &eblock,
			      i_vector)) {
        goto clean_prockey;
    }


    /* put last block into the i_vector */
    if (i_vector)
	memcpy(i_vector,
	       privmsg.enc_part.ciphertext.data +
	       (privmsg.enc_part.ciphertext.length -
	        eblock.crypto_entry->block_length),
	       eblock.crypto_entry->block_length);
	   
    /* private message is now assembled-- do some cleanup */
    cleanup_scratch();

    if (retval = krb5_finish_key(&eblock)) {
        cleanup_encpart();
        return retval;
    }
    /* encode private message */
    if (retval = encode_krb5_priv(&privmsg, &scratch))  {
        cleanup_encpart();
	return retval;
    }

    cleanup_encpart();
    *outbuf = *scratch;
    free((char *)scratch);
    return 0;

 clean_prockey:
    cleanup_prockey();
 clean_encpart:
    cleanup_encpart();
 clean_scratch:
    cleanup_scratch();

    return retval;
}

