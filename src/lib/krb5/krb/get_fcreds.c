/*
 * lib/krb5/krb/get_fcreds.c
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
 * krb5_get_for_creds()
 */

/* XXX This API is going to change; what's here isn't general enough! XXX */
/* XXX Once we finalize the API, it should go into func-proto.h and */
/* into the API doc. */

/* General-purpose forwarding routines. These routines may be put into */
/* libkrb5.a to allow widespread use */ 

#define NEED_SOCKETS
#include "k5-int.h"
#include <stdio.h>

#define KRB5_DEFAULT_LIFE 60*60*8   /* 8 hours */
/* helper function: convert flags to necessary KDC options */
#define flags2options(flags) (flags & KDC_TKT_COMMON_MASK)

/* Get a TGT for use at the remote host */
krb5_error_code INTERFACE
krb5_get_for_creds(context, sumtype, rhost, client, enc_key, 
		   forwardable, outbuf)
    krb5_context context;
    const krb5_cksumtype sumtype;
    char *rhost;
    krb5_principal client;
    krb5_keyblock *enc_key;
    int forwardable;      /* Should forwarded TGT also be forwardable? */
    krb5_data *outbuf;
{
    struct hostent *hp;
    krb5_enctype etype;
    krb5_address **addrs;
    krb5_error_code retval;
    krb5_kdc_rep *dec_rep = 0;
    krb5_error *err_reply;
    krb5_response tgsrep;
    krb5_creds creds, tgt;
    krb5_ccache cc;
    krb5_flags kdcoptions;
    krb5_timestamp now;
    char *remote_host = 0;
    char **hrealms = 0;
    int i;

    memset((char *)&creds, 0, sizeof(creds));
    memset((char *)&tgsrep, 0, sizeof(tgsrep));

    if (!rhost || !(hp = gethostbyname(rhost)))
      return KRB5_ERR_BAD_HOSTNAME;

    remote_host = (char *) malloc(strlen(hp->h_name)+1);
    if (!remote_host) {
	retval = ENOMEM;
	goto errout;
    }	
    strcpy(remote_host, hp->h_name);

    if (retval = krb5_get_host_realm(context, remote_host, &hrealms))
	goto errout;
    if (!hrealms[0]) {
	retval = KRB5_ERR_HOST_REALM_UNKNOWN;
	goto errout;
    }

    /* Count elements */
    for(i=0; hp->h_addr_list[i]; i++);

    addrs = (krb5_address **) malloc ((i+1)*sizeof(*addrs));
    if (!addrs) {
	retval = ENOMEM;
	goto errout;
    }
    memset(addrs, 0, (i+1)*sizeof(*addrs));
    
    for(i=0; hp->h_addr_list[i]; i++) {
	addrs[i] = (krb5_address *) malloc(sizeof(krb5_address));
	if (!addrs[i]) {
	    retval = ENOMEM;
	    goto errout;
	}
	addrs[i]->addrtype = hp->h_addrtype;
	addrs[i]->length   = hp->h_length;
	addrs[i]->contents = (unsigned char *)malloc(addrs[i]->length);
	if (!addrs[i]->contents) {
	    retval = ENOMEM;
	    goto errout;
	}
	memcpy ((char *)addrs[i]->contents, hp->h_addr_list[i],
		addrs[i]->length);
    }
    addrs[i] = 0;

    if (retval = krb5_copy_principal(context, client, &creds.client))
	goto errout;
    
    if (retval = krb5_build_principal_ext(context, &creds.server,
					  strlen(hrealms[0]),
					  hrealms[0],
					  KRB5_TGS_NAME_SIZE,
					  KRB5_TGS_NAME,
					  client->realm.length,
					  client->realm.data,
					  0))
	goto errout;
	
    creds.times.starttime = 0;
    if (retval = krb5_timeofday(context, &now))
	goto errout;

    creds.times.endtime = now + KRB5_DEFAULT_LIFE;
    creds.times.renew_till = 0;
    
    if (retval = krb5_cc_default(context, &cc))
	goto errout;

    /* fetch tgt directly from cache */
    retval = krb5_cc_retrieve_cred (context, cc, KRB5_TC_MATCH_SRV_NAMEONLY,
				    &creds, &tgt);
    krb5_cc_close(context, cc);
    if (retval)
	goto errout;

    /* tgt->client must be equal to creds.client */
    if (!krb5_principal_compare(context, tgt.client, creds.client)) {
	retval = KRB5_PRINC_NOMATCH;
	goto errout;
    }

    if (!tgt.ticket.length) {
	retval = KRB5_NO_TKT_SUPPLIED;
	goto errout;
    }

    kdcoptions = flags2options(tgt.ticket_flags)|KDC_OPT_FORWARDED;

    if (!forwardable) /* Reset KDC_OPT_FORWARDABLE */
      kdcoptions &= ~(KDC_OPT_FORWARDABLE);

    if (retval = krb5_send_tgs(context, kdcoptions, &creds.times, NULL, 
			       sumtype, tgt.server, addrs, creds.authdata,
			       0,		/* no padata */
			       0,		/* no second ticket */
			       &tgt, &tgsrep))
	goto errout;

    switch (tgsrep.message_type) {
    case KRB5_TGS_REP:
	break;
    case KRB5_ERROR:
    default:
	if (!krb5_is_krb_error(&tgsrep.response)) {
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto errout;
	} else {
	    if (retval = decode_krb5_error(&tgsrep.response, &err_reply))
		goto errout;
	}

	retval = err_reply->error + ERROR_TABLE_BASE_krb5;

	krb5_free_error(context, err_reply);
	goto errout;
    }
    
    etype = tgt.keyblock.etype;
    if (retval = krb5_decode_kdc_rep(context, &tgsrep.response,
				     &tgt.keyblock,
				     etype, /* enctype */
				     &dec_rep))
	goto errout;
    
    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	goto errout;
    }
    
    /* now it's decrypted and ready for prime time */

    if (!krb5_principal_compare(context, dec_rep->client, tgt.client)) {
	retval = KRB5_KDCREP_MODIFIED;
	goto errout;
    }

    retval = krb5_mk_cred(context, dec_rep, etype, enc_key, 0, 0, outbuf);
    
errout:
    if (remote_host)
	free(remote_host);
    if (hrealms)
	krb5_xfree(hrealms);
    if (addrs)
	krb5_free_addresses(context, addrs);
    krb5_free_cred_contents(context, &creds);
    if (tgsrep.response.data)
	free(tgsrep.response.data);
    if (dec_rep)
	krb5_free_kdc_rep(context, dec_rep); 
    return retval;
}
