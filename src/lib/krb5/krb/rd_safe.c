/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_rd_safe()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rd_safe_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/krb5_err.h>

#include <krb5/asn1.h>
#include <stdio.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>

extern krb5_deltat krb5_clockskew;
#define in_clock_skew(date) (abs((date)-currenttime) < krb5_clockskew)

/*
 parses a KRB_SAFE message from inbuf, placing the integrity-protected user
 data in *outbuf.

 key specifies the key to be used for decryption of the message.
 
 sender_addr and recv_addr specify the full addresses (host and port) of
 the sender and receiver.

 outbuf points to allocated storage which the caller should free when finished.

 returns system errors, integrity errors
 */
krb5_error_code
krb5_rd_safe(inbuf, key, sender_addr, recv_addr, outbuf)
krb5_data *inbuf;
krb5_keyblock *key;
krb5_fulladdr *sender_addr;
krb5_fulladdr *recv_addr;
krb5_data *outbuf;
{
    krb5_error_code retval;
    krb5_safe *message;
    krb5_ui_2 computed_direction;
    krb5_checksum our_cksum, *his_cksum;
    krb5_octet zero_octet = 0;
    krb5_data *scratch;
    krb5_timestamp currenttime;

    if (!krb5_is_krb_safe(inbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;

    if (retval = decode_krb5_safe(inbuf, &message))
	return retval;

#define cleanup() krb5_free_safe(message)

    if (!valid_cksumtype(message->checksum->checksum_type))
	return KRB5_PROG_SUMTYPE_NOSUPP;

    /* length bounds check XXX ?? how */
    
    if (sender_addr && !krb5_address_search(sender_addr->address,
					    message->addresses)) {
	cleanup();
	return KRB5KRB_AP_ERR_BADADDR;
    }

    if (retval = krb5_timeofday(&currenttime)) {
	cleanup();
	return retval;
    }
    if (!in_clock_skew(message->timestamp)) {
	cleanup();
	return KRB5KRB_AP_ERR_SKEW;
    }

    /* replay detection goes here... XXX */
    computed_direction = (krb5_fulladdr_order(sender_addr, recv_addr) > 0) ?
	                 MSEC_DIRBIT : 0; 
    /* what if sender_addr == 0 ?????*/
    if (computed_direction != message->msec & MSEC_DIRBIT) {
	cleanup();
	return KRB5KRB_AP_ERR_REPEAT;	/* XXX */
    }

    /* verify the checksum */
    /* to do the checksum stuff, we need to re-encode the message with a
       zero-length zero-type checksum, then checksum the encoding, and verify.
     */
    his_cksum = message->checksum;

    our_cksum.checksum_type = 0;
    our_cksum.length = 0;
    our_cksum.contents = &zero_octet;

    message->checksum = &our_cksum;

    if (retval = encode_krb5_safe(&message, &scratch)) {
	message->checksum = his_cksum;
	cleanup();
	return retval;
    }
			 
    retval = (*(krb5_cksumarray[his_cksum->checksum_type]->
		sum_func))(scratch->data,
			   0, /* XXX? */
			   (krb5_pointer) key->contents,
			   scratch->length,
			   key->length,
			   &our_cksum);
    (void) bzero((char *)scratch->data, scratch->length);
    krb5_free_data(scratch);
    
    if (retval) {
	cleanup();
	return retval;
    }

#undef cleanup
#define cleanup() {krb5_free_safe(message); xfree(our_cksum.contents);}

    if (our_cksum.length != his_cksum->length ||
	bcmp((char *)our_cksum.contents, (char *)his_cksum->contents,
	     our_cksum.length)) {
	cleanup();
	return KRB5KRB_AP_ERR_MODIFIED;
    }

    *outbuf = message->user_data;

    xfree(our_cksum.contents);
    if (message->addresses)
	krb5_free_address(message->addresses);
    krb5_free_checksum(his_cksum);
    xfree(message);

    return 0;
}
