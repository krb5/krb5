/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_rd_priv()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_priv_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/krb5_err.h>

#include <errno.h>

#include <krb5/asn1.h>
#include <stdio.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>

extern krb5_deltat krb5_clockskew;   
#define in_clock_skew(date) (abs((date)-currenttime) < krb5_clockskew)

krb5_error_code
krb5_rd_priv(DECLARG(const krb5_data *, inbuf),
	     DECLARG(const krb5_keyblock *, key),
	     DECLARG(const krb5_fulladdr *, sender_addr),
	     DECLARG(const krb5_fulladdr *, recv_addr),
	     DECLARG(krb5_data *, outbuf))
OLDDECLARG(const krb5_data *, inbuf)
OLDDECLARG(const krb5_keyblock *, key)
OLDDECLARG(const krb5_fulladdr *, sender_addr)
OLDDECLARG(const krb5_fulladdr *, recv_addr)
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
    
#define cleanup_privmsg() {(void)xfree(privmsg->enc_part.data); (void)xfree(privmsg);}
    if (!valid_etype(privmsg->etype)) {
	cleanup_privmsg();
	return KRB5_PROG_ETYPE_NOSUPP; /* XXX */
    }
			   
    /* put together an eblock for this decryption */

    eblock.crypto_entry = krb5_csarray[privmsg->etype]->system;
    scratch.length = privmsg->enc_part.length;
    
    if (!(scratch.data = malloc(scratch.length))) {
	cleanup_privmsg();
        return ENOMEM;
    }

#define cleanup_scratch() {(void)bzero(scratch.data, scratch.length); (void)xfree(scratch.data);}

    /* do any necessary key pre-processing */
    if (retval = (*eblock.crypto_entry->process_key)(&eblock, key)) {
        cleanup_privmsg();
	cleanup_scratch();
	return retval;
    }

#define cleanup_prockey() {(void) (*eblock.crypto_entry->finish_key)(&eblock);}

    /* call the decryption routine */
    if (retval =
        (*eblock.crypto_entry->decrypt_func)((krb5_pointer) privmsg->enc_part.data,
                                             (krb5_pointer) scratch.data,
                                             scratch.length, &eblock)) {
	cleanup_privmsg();
	cleanup_scratch();
        cleanup_prockey();
	return retval;
    }

    /* private message is now decrypted -- do some cleanup */

    cleanup_privmsg();

    if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
        cleanup_scratch();
        return retval;
    }

    /*  now decode the decrypted stuff */
    if (retval = decode_krb5_enc_priv_part(&scratch, &privmsg_enc_part)) {
	cleanup_scratch();
	return retval;
    }
    cleanup_scratch();

#define cleanup_data() {(void)bzero(privmsg_enc_part->user_data.data,privmsg_enc_part->user_data.length); (void)xfree(privmsg_enc_part->user_data.data);}
#define cleanup_mesg() {(void)xfree(privmsg_enc_part);}

    if (sender_addr && !krb5_address_compare(sender_addr->address,
					  privmsg_enc_part->addresses[0])) {
	cleanup_data();
	cleanup_mesg();
	return KRB5KRB_AP_ERR_BADADDR;
    }

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

    computed_direction = (krb5_fulladdr_order(sender_addr, recv_addr) > 0) ?
	                 MSEC_DIRBIT : 0; 
    /* what if sender_addr == 0 ?????*/
    if (computed_direction != privmsg_enc_part->msec & MSEC_DIRBIT) {
	cleanup_data();
	cleanup_mesg();
	return KRB5KRB_AP_ERR_REPEAT;
    }

    /* everything is ok - return data to the user */

    *outbuf = privmsg_enc_part->user_data;
    cleanup_mesg();
    return 0;

}

