#include <k5-int.h>
#include "cleanup.h"
#include "auth_con.h"

#include <stddef.h>           /* NULL */
#include <stdlib.h>           /* malloc */
#include <errno.h>            /* ENOMEM */

/*-------------------- decrypt_credencdata --------------------*/

/*
 * decrypt the enc_part of a krb5_cred
 */
static krb5_error_code 
decrypt_credencdata(context, pcred, pkeyblock, pcredenc)
    krb5_context	  context;
    krb5_cred 		* pcred;
    krb5_keyblock 	* pkeyblock;
    krb5_cred_enc_part 	* pcredenc;
{
    krb5_cred_enc_part  * ppart;
    krb5_encrypt_block 	  eblock;
    krb5_error_code 	  retval;
    krb5_data 		  scratch;

    scratch.length = pcred->enc_part.ciphertext.length;
    if (!(scratch.data = (char *)malloc(scratch.length))) 
	return ENOMEM;

    if (pkeyblock != NULL) {
	if (!valid_enctype(pcred->enc_part.enctype)) {
	    free(scratch.data);
	    return KRB5_PROG_ETYPE_NOSUPP;
	}

	/* put together an eblock for this decryption */
	krb5_use_enctype(context, &eblock, pcred->enc_part.enctype);
    
	/* do any necessary key pre-processing */
	if ((retval = krb5_process_key(context, &eblock, pkeyblock)))
	    goto cleanup;
    
	/* call the decryption routine */
	if ((retval = krb5_decrypt(context, 
			   (krb5_pointer) pcred->enc_part.ciphertext.data,
			   (krb5_pointer) scratch.data,
			   scratch.length, &eblock, 0))) {
	    (void)krb5_finish_key(context, &eblock);
	    goto cleanup;
	}

	if ((retval = krb5_finish_key(context, &eblock)))
	    goto cleanup;
    } else {
	memcpy(scratch.data, pcred->enc_part.ciphertext.data, scratch.length);
    }

    /*  now decode the decrypted stuff */
    if ((retval = decode_krb5_enc_cred_part(&scratch, &ppart)))
    	goto cleanup_encpart;

    *pcredenc = *ppart;
    retval = 0;

cleanup_encpart:
    memset(ppart, 0, sizeof(*ppart));
    krb5_xfree(ppart);

cleanup:
    memset(scratch.data, 0, scratch.length);
    krb5_xfree(scratch.data);

    return retval;
}
/*----------------------- krb5_rd_cred_basic -----------------------*/

static krb5_error_code 
krb5_rd_cred_basic(context, pcreddata, pkeyblock, local_addr, remote_addr,
		   replaydata, pppcreds)
    krb5_context          context;
    krb5_data		* pcreddata;
    krb5_keyblock 	* pkeyblock;
    krb5_address  	* local_addr;
    krb5_address  	* remote_addr;
    krb5_replay_data    * replaydata;
    krb5_creds        *** pppcreds;
{
    krb5_error_code       retval;
    krb5_cred 		* pcred;
    krb5_int32 		  ncreds;
    krb5_int32 		  i = 0;
    krb5_cred_enc_part 	  encpart;

    /* decode cred message */
    if ((retval = decode_krb5_cred(pcreddata, &pcred)))
    	return retval;

    memset(&encpart, sizeof(encpart), 0);

    if ((retval = decrypt_credencdata(context, pcred, pkeyblock, &encpart)))
	goto cleanup_cred;

    /*
     * Only check the remote address if the KRB_CRED message was
     * protected by encryption.  If it came in the checksum field of
     * an init_sec_context message, skip over this check.
     */
    if (pkeyblock != NULL) {
	if (!krb5_address_compare(context, remote_addr, encpart.s_address)) {
	    retval = KRB5KRB_AP_ERR_BADADDR;
	    goto cleanup_cred;
	}
    }

    if (encpart.r_address) {
        if (local_addr) {
            if (!krb5_address_compare(context, local_addr, encpart.r_address)) {
                retval = KRB5KRB_AP_ERR_BADADDR;
                goto cleanup_cred;
            }
        } else {
            krb5_address **our_addrs;

            if ((retval = krb5_os_localaddr(context, &our_addrs))) {
                goto cleanup_cred;
            }
            if (!krb5_address_search(context, encpart.r_address, our_addrs)) {
                krb5_free_addresses(context, our_addrs);
                retval =  KRB5KRB_AP_ERR_BADADDR;
                goto cleanup_cred;
            }
            krb5_free_addresses(context, our_addrs);
        }
    }

    replaydata->timestamp = encpart.timestamp;
    replaydata->usec = encpart.usec;
    replaydata->seq = encpart.nonce;

   /*
    * Allocate the list of creds.  The memory is allocated so that
    * krb5_free_tgt_creds can be used to free the list.
    */
    for (ncreds = 0; pcred->tickets[ncreds]; ncreds++);
	
    if ((*pppcreds = 
        (krb5_creds **)malloc((size_t)(sizeof(krb5_creds *) *
				       (ncreds + 1)))) == NULL) {
        retval = ENOMEM;
        goto cleanup_cred;
    }
    (*pppcreds)[0] = NULL;

    /*
     * For each credential, create a strcture in the list of
     * credentials and copy the information.
     */
    while (i < ncreds) {
        krb5_cred_info 	* pinfo;
        krb5_creds 	* pcur;
	krb5_data	* pdata;

        if ((pcur = (krb5_creds *)malloc(sizeof(krb5_creds))) == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
        }

        (*pppcreds)[i] = pcur;
        (*pppcreds)[i+1] = 0;
        pinfo = encpart.ticket_info[i++];
        memset(pcur, 0, sizeof(krb5_creds));

        if ((retval = krb5_copy_principal(context, pinfo->client,
					  &pcur->client)))
	    goto cleanup;

        if ((retval = krb5_copy_principal(context, pinfo->server,
					  &pcur->server)))
	    goto cleanup;

      	if ((retval = krb5_copy_keyblock_contents(context, pinfo->session,
						  &pcur->keyblock)))
	    goto cleanup;

        if ((retval = krb5_copy_addresses(context, pinfo->caddrs, 
					  &pcur->addresses)))
	    goto cleanup;

        if ((retval = encode_krb5_ticket(pcred->tickets[i - 1], &pdata)))
	    goto cleanup;

	pcur->ticket = *pdata;
	krb5_xfree(pdata);


        pcur->is_skey = FALSE;
        pcur->magic = KV5M_CREDS;
        pcur->times = pinfo->times;
        pcur->ticket_flags = pinfo->flags;
        pcur->authdata = NULL;   /* not used */
        memset(&pcur->second_ticket, 0, sizeof(pcur->second_ticket));
    }

    /*
     * NULL terminate the list
     */
    (*pppcreds)[i] = NULL;

cleanup:
    if (retval)
	krb5_free_tgt_creds(context, *pppcreds);

cleanup_cred:
    krb5_free_cred(context, pcred);
    krb5_free_cred_enc_part(context, &encpart);

    return retval;
}

/*----------------------- krb5_rd_cred -----------------------*/

#define in_clock_skew(date) (labs((date)-currenttime) < context->clockskew)

/*
 * This functions takes as input an KRB_CRED message, validates it, and
 * outputs the nonce and an array of the forwarded credentials.
 */
krb5_error_code
krb5_rd_cred(context, auth_context, pcreddata, pppcreds, outdata)
    krb5_context          context;
    krb5_auth_context     auth_context;
    krb5_data 		* pcreddata;       
    krb5_creds        *** pppcreds;
    krb5_replay_data  	* outdata;
{
    krb5_error_code       retval;
    krb5_keyblock       * keyblock;
    krb5_replay_data      replaydata;

    /* Get keyblock */
    if ((keyblock = auth_context->local_subkey) == NULL)
        if ((keyblock = auth_context->remote_subkey) == NULL)
            keyblock = auth_context->keyblock;

    if (((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME) ||
      (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) &&
      (outdata == NULL))
        /* Need a better error */
        return KRB5_RC_REQUIRED;

    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) &&
      (auth_context->rcache == NULL))
        return KRB5_RC_REQUIRED;

{
    krb5_address * premote_fulladdr = NULL;
    krb5_address * plocal_fulladdr = NULL;
    krb5_address remote_fulladdr;
    krb5_address local_fulladdr;
    CLEANUP_INIT(2);

    if (auth_context->local_addr) {
    	if (auth_context->local_port) {
            if (!(retval = krb5_make_fulladdr(context,auth_context->local_addr,
                                 	      auth_context->local_port, 
					      &local_fulladdr))){
                CLEANUP_PUSH(local_fulladdr.contents, free);
	        plocal_fulladdr = &local_fulladdr;
            } else {
	        return retval;
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
	        return retval;
            }
	} else {
            premote_fulladdr = auth_context->remote_addr;
        }
    }

    if ((retval = krb5_rd_cred_basic(context, pcreddata, keyblock,
				     plocal_fulladdr, premote_fulladdr,
				     &replaydata, pppcreds))) {
        CLEANUP_DONE();
	return retval;
    }

    CLEANUP_DONE();
}


    if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) {
        krb5_donot_replay replay;
        krb5_timestamp currenttime;

        if ((retval = krb5_timeofday(context, &currenttime)))
            goto error;

        if (!in_clock_skew(replaydata.timestamp)) {
            retval =  KRB5KRB_AP_ERR_SKEW;
            goto error;
        }

        if ((retval = krb5_gen_replay_name(context, auth_context->remote_addr,
					   "_forw", &replay.client)))
            goto error;

        replay.server = "";             /* XXX */
        replay.cusec = replaydata.usec;
        replay.ctime = replaydata.timestamp;
        if ((retval = krb5_rc_store(context, auth_context->rcache, &replay))) {
            krb5_xfree(replay.client);
            goto error;
        }
        krb5_xfree(replay.client);
    }

    if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
        if (auth_context->remote_seq_number != replaydata.seq) {
            retval =  KRB5KRB_AP_ERR_BADORDER;
            goto error;
        }
        auth_context->remote_seq_number++;
    }

    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME) ||
      (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) {
        outdata->timestamp = replaydata.timestamp;
        outdata->usec = replaydata.usec;
        outdata->seq = replaydata.seq;
    }

error:;
    if (retval)
    	krb5_xfree(*pppcreds);
    return retval;
}


