/*
 * lib/krb5/krb/mk_priv.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 *
 * krb5_mk_priv()
 */

#include "k5-int.h"
#include "cleanup.h"
#include "auth_con.h"

static krb5_error_code
krb5_mk_priv_basic(context, userdata, keyblock, replaydata, local_addr, 
		   remote_addr, i_vector, outbuf)
    krb5_context 	  context;
    const krb5_data   	* userdata;
    const krb5_keyblock * keyblock;
    krb5_replay_data  	* replaydata;
    krb5_address      	* local_addr;
    krb5_address      	* remote_addr;
    krb5_pointer	  i_vector;
    krb5_data         	* outbuf; 
{
    krb5_error_code 	retval;
    krb5_encrypt_block 	eblock;
    krb5_priv 		privmsg;
    krb5_priv_enc_part 	privmsg_enc_part;
    krb5_data 		*scratch1, *scratch2;

    if (!valid_enctype(keyblock->enctype))
	return KRB5_PROG_ETYPE_NOSUPP;

    privmsg.enc_part.kvno = 0;	/* XXX allow user-set? */
    privmsg.enc_part.enctype = keyblock->enctype; 

    privmsg_enc_part.user_data = *userdata;
    privmsg_enc_part.s_address = local_addr;
    privmsg_enc_part.r_address = remote_addr;

    /* We should check too make sure one exists. */
    privmsg_enc_part.timestamp  = replaydata->timestamp;
    privmsg_enc_part.usec 	= replaydata->usec;
    privmsg_enc_part.seq_number = replaydata->seq;

    /* start by encoding to-be-encrypted part of the message */
    if ((retval = encode_krb5_enc_priv_part(&privmsg_enc_part, &scratch1)))
	return retval;

    /* put together an eblock for this encryption */
    krb5_use_enctype(context, &eblock, keyblock->enctype);
    privmsg.enc_part.ciphertext.length = krb5_encrypt_size(scratch1->length,
						eblock.crypto_entry);
    /* add padding area, and zero it */
    if (!(scratch1->data = realloc(scratch1->data,
				  privmsg.enc_part.ciphertext.length))) {
	/* may destroy scratch1->data */
	krb5_xfree(scratch1);
	return ENOMEM;
    }

    memset(scratch1->data + scratch1->length, 0,
	  privmsg.enc_part.ciphertext.length - scratch1->length);
    if (!(privmsg.enc_part.ciphertext.data =
	  malloc(privmsg.enc_part.ciphertext.length))) {
        retval = ENOMEM;
        goto clean_scratch;
    }

    /* do any necessary key pre-processing */
    if ((retval = krb5_process_key(context, &eblock, keyblock)))
        goto clean_encpart;

    /* call the encryption routine */
    if ((retval = krb5_encrypt(context, (krb5_pointer) scratch1->data,
			       (krb5_pointer) privmsg.enc_part.ciphertext.data,
			       scratch1->length, &eblock, i_vector))) {
    	krb5_finish_key(context, &eblock);
        goto clean_encpart;
    }

    /* put last block into the i_vector */
    if (i_vector)
	memcpy(i_vector,
	       privmsg.enc_part.ciphertext.data +
	       (privmsg.enc_part.ciphertext.length -
	        eblock.crypto_entry->block_length),
	       eblock.crypto_entry->block_length);
	   
    if ((retval = encode_krb5_priv(&privmsg, &scratch2)))  {
    	krb5_finish_key(context, &eblock);
        goto clean_encpart;
    }

    /* encode private message */
    if ((retval = krb5_finish_key(context, &eblock)))
        goto clean_encpart;

    *outbuf = *scratch2;
    krb5_xfree(scratch2);
    retval = 0;

clean_encpart:
    memset(privmsg.enc_part.ciphertext.data, 0, 
	   privmsg.enc_part.ciphertext.length); 
    free(privmsg.enc_part.ciphertext.data); 
    privmsg.enc_part.ciphertext.length = 0;
    privmsg.enc_part.ciphertext.data = 0;

clean_scratch:
    memset(scratch1->data, 0, scratch1->length);
    krb5_free_data(context, scratch1); 

    return retval;
}


KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_mk_priv(context, auth_context, userdata, outbuf, outdata)
    krb5_context 	  context;
    krb5_auth_context 	  auth_context;
    const krb5_data   	FAR * userdata;
    krb5_data         	FAR * outbuf;
    krb5_replay_data  	FAR * outdata;
{
    krb5_error_code 	  retval;
    krb5_keyblock       * keyblock;
    krb5_replay_data      replaydata;

    /* Clear replaydata block */
    memset((char *) &replaydata, 0, sizeof(krb5_replay_data));

    /* Get keyblock */
    if ((keyblock = auth_context->local_subkey) == NULL)
        if ((keyblock = auth_context->remote_subkey) == NULL)
            keyblock = auth_context->keyblock;

    /* Get replay info */
    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) &&
      (auth_context->rcache == NULL))
	return KRB5_RC_REQUIRED;

    if (((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME) ||
      (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) &&
      (outdata == NULL))
	/* Need a better error */
	return KRB5_RC_REQUIRED;

    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) ||
	(auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME)) {
	if ((retval = krb5_us_timeofday(context, &replaydata.timestamp,
					&replaydata.usec)))
	    return retval;
	if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME) {
    	    outdata->timestamp = replaydata.timestamp;
    	    outdata->usec = replaydata.usec;
	}
    }
    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) ||
	(auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) {
	replaydata.seq = auth_context->local_seq_number;
	if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
	    auth_context->local_seq_number++;
	} else {
    	    outdata->seq = replaydata.seq;
	}
    } 

{
    krb5_address * premote_fulladdr = NULL;
    krb5_address * plocal_fulladdr = NULL;
    krb5_address remote_fulladdr;
    krb5_address local_fulladdr;
    CLEANUP_INIT(2);

    if (auth_context->local_addr) {
	if (auth_context->local_port) {
	    if (!(retval = krb5_make_fulladdr(context, auth_context->local_addr,
				  	      auth_context->local_port, 
					      &local_fulladdr))) {
	    	CLEANUP_PUSH(local_fulladdr.contents, free);
	    	plocal_fulladdr = &local_fulladdr;
            } else {
    	    	goto error;
            }
	} else {
	    plocal_fulladdr = auth_context->local_addr;
	}
    }

    if (auth_context->remote_addr) {
    	if (auth_context->remote_port) {
	    if (!(retval = krb5_make_fulladdr(context,auth_context->remote_addr,
				 	      auth_context->remote_port, 
					      &remote_fulladdr))){
	    	CLEANUP_PUSH(remote_fulladdr.contents, free);
	    	premote_fulladdr = &remote_fulladdr;
 	    } else {
	        CLEANUP_DONE();
	        goto error;
	    }
	} else {
	    premote_fulladdr = auth_context->remote_addr;
	}
    }

    if ((retval = krb5_mk_priv_basic(context, userdata, keyblock, &replaydata, 
				     plocal_fulladdr, premote_fulladdr,
				     auth_context->i_vector, outbuf))) {
	CLEANUP_DONE();
	goto error;
    }

    CLEANUP_DONE();
}

    if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) {
	krb5_donot_replay replay;

	if ((retval = krb5_gen_replay_name(context, auth_context->local_addr, 
					   "_priv", &replay.client))) {
    	    krb5_xfree(outbuf);
	    goto error;
	}

	replay.server = "";		/* XXX */
	replay.cusec = replaydata.usec;
	replay.ctime = replaydata.timestamp;
	if ((retval = krb5_rc_store(context, auth_context->rcache, &replay))) {
	    /* should we really error out here? XXX */
    	    krb5_xfree(replay.client);
	    goto error;
	}
	krb5_xfree(replay.client);
    }

    return 0;

error:
    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) ||
      (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE))
	auth_context->local_seq_number--;

    return retval;
}

