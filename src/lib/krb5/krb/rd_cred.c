/*
 * lib/krb5/krb/rd_cred.c
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
 * krb5_rd_cred()
 */

/* XXX This API is going to change; what's here isn't general enough! */
/* XXX Once we finalize the API, it should go into func-proto.h and */
/* into the API doc. */

#include "k5-int.h"

extern krb5_deltat krb5_clockskew;
#define in_clock_skew(date) (labs((date)-currenttime) < krb5_clockskew)

/* Decode the KRB-CRED message, and return creds */
krb5_error_code INTERFACE
krb5_rd_cred(context, inbuf, key, creds, sender_addr, recv_addr)
    krb5_context context;
    const krb5_data *inbuf;
    const krb5_keyblock *key;
    krb5_creds *creds;                /* Filled in */
    const krb5_address *sender_addr;  /* optional */
    const krb5_address *recv_addr;    /* optional */
{
    krb5_error_code retval;
    krb5_encrypt_block eblock;
    krb5_cred *credmsg;
    krb5_cred_enc_part *credmsg_enc_part;
    krb5_data *scratch;
    krb5_timestamp currenttime;

    if (!krb5_is_krb_cred(inbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;
    
    /* decode private message */
    if (retval = decode_krb5_cred(inbuf, &credmsg))  {
	return retval;
    }
    
#define cleanup_credmsg() {(void)krb5_xfree(credmsg->enc_part.ciphertext.data); (void)krb5_xfree(credmsg);}

    if (!(scratch = (krb5_data *) malloc(sizeof(*scratch)))) {
	cleanup_credmsg();
	return ENOMEM;
    }

#define cleanup_scratch() {(void)memset(scratch->data, 0, scratch->length); (void)krb5_xfree(scratch->data);}

    if (retval = encode_krb5_ticket(credmsg->tickets[0], &scratch)) {
	cleanup_credmsg();
	cleanup_scratch();
	return(retval);
    }

    creds->ticket = *scratch;
    if (!(creds->ticket.data = malloc(scratch->length))) {
	krb5_xfree(creds->ticket.data);
	return ENOMEM;
    }
    memcpy((char *)creds->ticket.data, (char *) scratch->data, scratch->length);

    cleanup_scratch();

    if (!valid_etype(credmsg->enc_part.etype)) {
	cleanup_credmsg();
	return KRB5_PROG_ETYPE_NOSUPP;
    }

    /* put together an eblock for this decryption */

    krb5_use_cstype(context, &eblock, credmsg->enc_part.etype);
    scratch->length = credmsg->enc_part.ciphertext.length;
    
    if (!(scratch->data = malloc(scratch->length))) {
	cleanup_credmsg();
        return ENOMEM;
    }

    /* do any necessary key pre-processing */
    if (retval = krb5_process_key(context, &eblock, key)) {
        cleanup_credmsg();
	cleanup_scratch();
	return retval;
    }
    
#define cleanup_prockey() {(void) krb5_finish_key(context, &eblock);}
    
    /* call the decryption routine */
    if (retval = krb5_decrypt(context, (krb5_pointer) credmsg->enc_part.ciphertext.data,
			      (krb5_pointer) scratch->data,
			      scratch->length, &eblock,
			      0)) {
	cleanup_credmsg();
	cleanup_scratch();
        cleanup_prockey();
	return retval;
    }

    /* cred message is now decrypted -- do some cleanup */

    cleanup_credmsg();

    if (retval = krb5_finish_key(context, &eblock)) {
        cleanup_scratch();
        return retval;
    }

    /*  now decode the decrypted stuff */
    if (retval = decode_krb5_enc_cred_part(scratch, &credmsg_enc_part)) {
	cleanup_scratch();
	return retval;
    }
    cleanup_scratch();

#define cleanup_mesg() {(void)krb5_xfree(credmsg_enc_part);}

    if (retval = krb5_timeofday(context, &currenttime)) {
	cleanup_mesg();
	return retval;
    }
    if (!in_clock_skew(credmsg_enc_part->timestamp)) {
	cleanup_mesg();  
	return KRB5KRB_AP_ERR_SKEW;
    }

    if (sender_addr && credmsg_enc_part->s_address &&
	!krb5_address_compare(context, sender_addr, 
			      credmsg_enc_part->s_address)) {
	cleanup_mesg();
	return KRB5KRB_AP_ERR_BADADDR;
    }
    if (recv_addr && credmsg_enc_part->r_address &&
	!krb5_address_compare(context, recv_addr, 
			      credmsg_enc_part->r_address)) {
	cleanup_mesg();
	return KRB5KRB_AP_ERR_BADADDR;
    }	    

    if (credmsg_enc_part->r_address) {
	krb5_address **our_addrs;
	
	if (retval = krb5_os_localaddr(&our_addrs)) {
	    cleanup_mesg();
	    return retval;
	}
	if (!krb5_address_search(context, credmsg_enc_part->r_address, 
				 our_addrs)) {
	    krb5_free_addresses(context, our_addrs);
	    cleanup_mesg();
	    return KRB5KRB_AP_ERR_BADADDR;
	}
	krb5_free_addresses(context, our_addrs);
    }

    if (retval = krb5_copy_principal(context, credmsg_enc_part->ticket_info[0]->client,
				     &creds->client)) {
	return(retval);
    }

    if (retval = krb5_copy_principal(context, credmsg_enc_part->ticket_info[0]->server,
				     &creds->server)) {
	return(retval);
    }  

    if (retval =
	krb5_copy_keyblock_contents(context, credmsg_enc_part->ticket_info[0]->session, 
				    &creds->keyblock)) {
	return(retval);
    }
    creds->keyblock.magic = KV5M_KEYBLOCK;
    creds->keyblock.etype = credmsg->tickets[0]->enc_part.etype;

#undef clean
#define clean() {\
	memset((char *)creds->keyblock.contents, 0, creds->keyblock.length);}

    creds->times = credmsg_enc_part->ticket_info[0]->times;
    creds->is_skey = FALSE;
    creds->ticket_flags = credmsg_enc_part->ticket_info[0]->flags;

    if (retval = krb5_copy_addresses(context, credmsg_enc_part->ticket_info[0]->caddrs,
				     &creds->addresses)) {
	clean();
	return(retval);
    }

    creds->second_ticket.length = 0;

    creds->authdata = 0;

    cleanup_mesg();
    return 0;
#undef clean
#undef cleanup_credmsg
#undef cleanup_scratch
#undef cleanup_prockey
#undef cleanup_mesg
}

