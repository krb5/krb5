/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_mk_safe()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mk_safe_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <krb5/asn1.h>
#include <krb5/libos-proto.h>
#include <krb5/ext-proto.h>

/*
 Formats a KRB_SAFE message into outbuf.

 userdata is formatted as the user data in the message.
 sumtype specifies the encryption type; key specifies the key which
 might be used to seed the checksum; sender_addr and recv_addr specify
 the full addresses (host and port) of the sender and receiver.
 The host portion of sender_addr is used to form the addresses used in the
 KRB_SAFE message.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 returns system errors
*/
krb5_error_code
krb5_mk_safe(DECLARG(const krb5_data *, userdata),
	     DECLARG(const krb5_cksumtype, sumtype),
	     DECLARG(const krb5_keyblock *, key),
	     DECLARG(const krb5_fulladdr *, sender_addr),
	     DECLARG(const krb5_fulladdr *, recv_addr),
	     DECLARG(krb5_data *, outbuf))
OLDDECLARG(const krb5_data *, userdata)
OLDDECLARG(const krb5_cksumtype, sumtype)
OLDDECLARG(const krb5_keyblock *, key)
OLDDECLARG(const krb5_fulladdr *, sender_addr)
OLDDECLARG(const krb5_fulladdr *, recv_addr)
OLDDECLARG(krb5_data *, outbuf)
{
    krb5_error_code retval;
    krb5_safe safemsg;
    krb5_address *addrs[2];
    krb5_octet zero_octet = 0;
    krb5_checksum safe_checksum;
    krb5_data *scratch;

    if (!valid_cksumtype(sumtype))
	return KRB5_PROG_SUMTYPE_NOSUPP;

    addrs[0] = sender_addr->address;
    addrs[1] = 0;

    safemsg.user_data = *userdata;
    safemsg.s_address = sender_addr->address;
    safemsg.r_address = recv_addr->address;

    if (retval = krb5_ms_timeofday(&safemsg.timestamp, &safemsg.msec))
	return retval;

    if (krb5_fulladdr_order(sender_addr, recv_addr) > 0)
	safemsg.msec = (safemsg.msec & MSEC_VAL_MASK) | MSEC_DIRBIT;
    else
	/* this should be a no-op, but just to be sure... */
	safemsg.msec = safemsg.msec & MSEC_VAL_MASK;

    /* to do the checksum stuff, we need to encode the message with a
       zero-length zero-type checksum, then checksum the encoding, then
       re-encode with the 
       checksum. */

    safe_checksum.checksum_type = 0;
    safe_checksum.length = 0;
    safe_checksum.contents = &zero_octet;

    safemsg.checksum = &safe_checksum;

    if (retval = encode_krb5_safe(&safemsg, &scratch))
	return retval;

#define clean_scratch() {(void) bzero((char *)scratch->data, scratch->length); krb5_free_data(scratch);}
			 
    if (!(safe_checksum.contents = (krb5_octet *)
	  malloc(krb5_cksumarray[sumtype]->checksum_length))) {
	clean_scratch();
	return ENOMEM;
    }
    if (retval = (*(krb5_cksumarray[sumtype]->sum_func))(scratch->data,
							 scratch->length,
							 (krb5_pointer) key->contents,
							 key->length,
							 &safe_checksum)) {
	xfree(safe_checksum.contents);
	clean_scratch();
	return retval;
    }
    safemsg.checksum = &safe_checksum;
    clean_scratch();
    if (retval = encode_krb5_safe(&safemsg, &scratch)) {
	xfree(safe_checksum.contents);
	return retval;
    }
    xfree(safe_checksum.contents);
    *outbuf = *scratch;
    free((char *)scratch);

    return 0;
}

