/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_rd_priv()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_priv_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/asn1.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>

extern krb5_deltat krb5_clockskew;   
#define in_clock_skew(date) (abs((date)-currenttime) < krb5_clockskew)

/*

Parses a KRB_PRIV message from inbuf, placing the confidential user
data in *outbuf.

key specifies the key to be used for decryption of the message.
 
sender_addr and recv_addr specify the full
addresses (host and port) of the sender and receiver.

outbuf points to allocated storage which the caller should
free when finished.

i_vector is used as an initialization vector for the
encryption, and if non-NULL its contents are replaced with the last
block of the encrypted data upon exit.

Returns system errors, integrity errors.

*/

krb5_error_code
krb5_rd_priv(DECLARG(const krb5_data *, inbuf),
	     DECLARG(const krb5_keyblock *, key),
	     DECLARG(const krb5_fulladdr *, sender_addr),
	     DECLARG(const krb5_fulladdr *, recv_addr),
	     DECLARG(krb5_pointer, i_vector),
	     DECLARG(krb5_data *, outbuf))
OLDDECLARG(const krb5_data *, inbuf)
OLDDECLARG(const krb5_keyblock *, key)
OLDDECLARG(const krb5_fulladdr *, sender_addr)
OLDDECLARG(const krb5_fulladdr *, recv_addr)
OLDDECLARG(krb5_pointer, i_vector)
OLDDECLARG(krb5_data *, outbuf)
{
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    krb5_priv *privmsg;
    krb5_priv_enc_part *privmsg_enc_part;
    krb5_data scratch;
    krb5_timestamp currenttime;
    krb5_ui_2 computed_direction;

    if (!krb5_is_krb_priv(inbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;
    /* decode private message */
    if (retval = decode_krb5_priv(inbuf, &privmsg))  {
	return retval;
    }
    
#define cleanup_privmsg() {(void)xfree(privmsg->enc_part.ciphertext.data); (void)xfree(privmsg);}
    if (!valid_etype(privmsg->enc_part.etype)) {
	cleanup_privmsg();
	return KRB5_PROG_ETYPE_NOSUPP;
    }
			   
    /* put together an eblock for this decryption */

    eblock.crypto_entry = krb5_csarray[privmsg->enc_part.etype]->system;
    scratch.length = privmsg->enc_part.ciphertext.length;
    
    if (!(scratch.data = malloc(scratch.length))) {
	cleanup_privmsg();
        return ENOMEM;
    }

#define cleanup_scratch() {(void)memset(scratch.data, 0, scratch.length); (void)xfree(scratch.data);}

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(&eblock, key)) {
        cleanup_privmsg();
	cleanup_scratch();
	return retval;
    }

#define cleanup_prockey() {(void) krb5_finish_key(&eblock);}

    /* call the decryption routine */
    if (retval = krb5_decrypt((krb5_pointer) privmsg->enc_part.ciphertext.data,
			      (krb5_pointer) scratch.data,
			      scratch.length, &eblock,
			      i_vector)) {
	cleanup_privmsg();
	cleanup_scratch();
        cleanup_prockey();
	return retval;
    }

    /* if i_vector is set, fill it in with the last block of the encrypted
       input */
    /* put last block into the i_vector */
    if (i_vector)
	memcpy(i_vector,
	       privmsg->enc_part.ciphertext.data +
	       (privmsg->enc_part.ciphertext.length -
	        eblock.crypto_entry->block_length),
	       eblock.crypto_entry->block_length);

    /* private message is now decrypted -- do some cleanup */

    cleanup_privmsg();

    if (retval = krb5_finish_key(&eblock)) {
        cleanup_scratch();
        return retval;
    }

    /*  now decode the decrypted stuff */
    if (retval = decode_krb5_enc_priv_part(&scratch, &privmsg_enc_part)) {
	cleanup_scratch();
	return retval;
    }
    cleanup_scratch();

#define cleanup_data() {(void)memset(privmsg_enc_part->user_data.data,0,privmsg_enc_part->user_data.length); (void)xfree(privmsg_enc_part->user_data.data);}
#define cleanup_mesg() {(void)xfree(privmsg_enc_part);}

    if (retval = krb5_timeofday(&currenttime)) {
	cleanup_data();
	cleanup_mesg();
	return retval;
    }
    if (!in_clock_skew(privmsg_enc_part->timestamp)) {
	cleanup_data();
	cleanup_mesg();  
	return KRB5KRB_AP_ERR_SKEW;
    }

    /* 
     * check with the replay cache should be inserted here !!!! 
     */


    if (sender_addr) {
	krb5_fulladdr temp_sender;
	krb5_fulladdr temp_recip;
	krb5_address **our_addrs;
	
	if (retval = krb5_os_localaddr(&our_addrs)) {
	    cleanup_data();
	    cleanup_mesg();
	    return retval;
	}
	if (!krb5_address_search(privmsg_enc_part->r_address, our_addrs)) {
	    krb5_free_address(our_addrs);
	    cleanup_data();
	    cleanup_mesg();
	    return KRB5KRB_AP_ERR_BADADDR;
	}
	krb5_free_address(our_addrs);

	temp_recip = *recv_addr;
	temp_recip.address = privmsg_enc_part->r_address;

	temp_sender = *sender_addr;
	temp_sender.address = privmsg_enc_part->s_address;

	computed_direction = ((krb5_fulladdr_order(&temp_sender, &temp_recip) >
			       0) ? MSEC_DIRBIT : 0); 
	if (computed_direction != (privmsg_enc_part->msec & MSEC_DIRBIT)) {
	    cleanup_data();
	    cleanup_mesg();
	    return KRB5KRB_AP_ERR_BADDIRECTION;
	}
    }

    /* everything is ok - return data to the user */

    *outbuf = privmsg_enc_part->user_data;
    cleanup_mesg();
    return 0;

}

