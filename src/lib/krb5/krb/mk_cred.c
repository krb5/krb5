/*
 * lib/krb5/krb/mk_cred.c
 *
 * Copyright 1994 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * krb5_mk_cred()
 */


/* XXX This API is going to change; what's here isn't general enough! */
/* XXX Once we finalize the API, it should go into func-proto.h and */
/* into the API doc. */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/asn1.h>

/* Create asn.1 encoded KRB-CRED message from the kdc reply. */
krb5_error_code
krb5_mk_cred(dec_rep, etype, key, sender_addr, recv_addr, outbuf)
krb5_kdc_rep *dec_rep;
krb5_enctype etype;
krb5_keyblock *key;
krb5_address *sender_addr;
krb5_address *recv_addr;
krb5_data *outbuf;
{
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    krb5_cred ret_cred;
    krb5_cred_enc_part cred_enc_part;
    krb5_data *scratch;

    if (!valid_etype(etype))
      return KRB5_PROG_ETYPE_NOSUPP;

    ret_cred.tickets = (krb5_ticket **) calloc(2, sizeof(*ret_cred.tickets));
    if (!ret_cred.tickets)
      return ENOMEM;
    ret_cred.tickets[0] = dec_rep->ticket;
    ret_cred.tickets[1] = 0;

    ret_cred.enc_part.etype = etype; 
    ret_cred.enc_part.kvno = 0;

    cred_enc_part.ticket_info = (krb5_cred_info **) 
      calloc(2, sizeof(*cred_enc_part.ticket_info));
    if (!cred_enc_part.ticket_info) {
	krb5_free_tickets(ret_cred.tickets);
	return ENOMEM;
    }
    cred_enc_part.ticket_info[0] = (krb5_cred_info *) 
      malloc(sizeof(*cred_enc_part.ticket_info[0]));
    if (!cred_enc_part.ticket_info[0]) {
	krb5_free_tickets(ret_cred.tickets);
	krb5_free_cred_enc_part(cred_enc_part);
	return ENOMEM;
    }
    cred_enc_part.nonce = 0;

    if (retval = krb5_us_timeofday(&cred_enc_part.timestamp,
				   &cred_enc_part.usec))
      return retval;

    cred_enc_part.s_address = (krb5_address *)sender_addr;
    cred_enc_part.r_address = (krb5_address *)recv_addr;

    cred_enc_part.ticket_info[0]->session = dec_rep->enc_part2->session;
    cred_enc_part.ticket_info[0]->client = dec_rep->client;
    cred_enc_part.ticket_info[0]->server = dec_rep->enc_part2->server;
    cred_enc_part.ticket_info[0]->flags  = dec_rep->enc_part2->flags;
    cred_enc_part.ticket_info[0]->times  = dec_rep->enc_part2->times;
    cred_enc_part.ticket_info[0]->caddrs = dec_rep->enc_part2->caddrs;

    cred_enc_part.ticket_info[1] = 0;

    /* start by encoding to-be-encrypted part of the message */

    if (retval = encode_krb5_enc_cred_part(&cred_enc_part, &scratch))
      return retval;

#define cleanup_scratch() { (void) memset(scratch->data, 0, scratch->length); krb5_free_data(scratch); }

    /* put together an eblock for this encryption */

    krb5_use_cstype(&eblock, etype);
    ret_cred.enc_part.ciphertext.length = krb5_encrypt_size(scratch->length,
						eblock.crypto_entry);
    /* add padding area, and zero it */
    if (!(scratch->data = realloc(scratch->data,
				  ret_cred.enc_part.ciphertext.length))) {
	/* may destroy scratch->data */
	krb5_xfree(scratch);
	return ENOMEM;
    }
    memset(scratch->data + scratch->length, 0,
	  ret_cred.enc_part.ciphertext.length - scratch->length);
    if (!(ret_cred.enc_part.ciphertext.data =
	  malloc(ret_cred.enc_part.ciphertext.length))) {
        retval = ENOMEM;
        goto clean_scratch;
    }

#define cleanup_encpart() {\
	(void) memset(ret_cred.enc_part.ciphertext.data, 0, \
	     ret_cred.enc_part.ciphertext.length); \
	free(ret_cred.enc_part.ciphertext.data); \
	ret_cred.enc_part.ciphertext.length = 0; \
	ret_cred.enc_part.ciphertext.data = 0;}

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(&eblock, key)) {
        goto clean_encpart;
    }

#define cleanup_prockey() {(void) krb5_finish_key(&eblock);}

    /* call the encryption routine */
    if (retval = krb5_encrypt((krb5_pointer) scratch->data,
			      (krb5_pointer)
			      ret_cred.enc_part.ciphertext.data, 
			      scratch->length, &eblock,
			      0)) {
        goto clean_prockey;
    }
    
    /* private message is now assembled-- do some cleanup */
    cleanup_scratch();

    if (retval = krb5_finish_key(&eblock)) {
        cleanup_encpart();
        return retval;
    }
    /* encode private message */
    if (retval = encode_krb5_cred(&ret_cred, &scratch))  {
        cleanup_encpart();
	return retval;
    }

    cleanup_encpart();

    *outbuf = *scratch;
    krb5_xfree(scratch);
    return 0;

 clean_prockey:
    cleanup_prockey();
 clean_encpart:
    cleanup_encpart();
 clean_scratch:
    cleanup_scratch();

    return retval;
#undef cleanup_prockey
#undef cleanup_encpart
#undef cleanup_scratch
}

