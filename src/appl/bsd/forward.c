/*
 * appl/bsd/forward.c
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* General-purpose forwarding routines. These routines may be put into */
/* libkrb5.a to allow widespread use */ 

#if defined(KERBEROS) || defined(KRB5)
#include <stdio.h>
#include <pwd.h>
#include <netdb.h>

#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/crc-32.h>
#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>

#define KRB5_DEFAULT_LIFE 60*60*8   /* 8 hours */
/* helper function: convert flags to necessary KDC options */
#define flags2options(flags) (flags & KDC_TKT_COMMON_MASK)

/* Get a TGT for use at the remote host */
krb5_error_code
get_for_creds(etype, sumtype, rhost, client, enc_key, forwardable, outbuf)
     const krb5_enctype etype;
     const krb5_cksumtype sumtype;
     char *rhost;
     krb5_principal client;
     krb5_keyblock *enc_key;
     int forwardable;      /* Should forwarded TGT also be forwardable? */
     krb5_data *outbuf;
{
    struct hostent *hp;
    krb5_address **addrs;
    krb5_error_code retval;
    krb5_data *scratch;
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

    if (retval = krb5_get_host_realm(remote_host, &hrealms))
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

    if (retval = krb5_copy_principal(client, &creds.client))
	goto errout;
    
    if (retval = krb5_build_principal_ext(&creds.server,
					  strlen(hrealms[0]),
					  hrealms[0],
					  KRB5_TGS_NAME_SIZE,
					  KRB5_TGS_NAME,
					  client->realm.length,
					  client->realm.data,
					  0))
	goto errout;
	
    creds.times.starttime = 0;
    if (retval = krb5_timeofday(&now))
	goto errout;

    creds.times.endtime = now + KRB5_DEFAULT_LIFE;
    creds.times.renew_till = 0;
    
    if (retval = krb5_cc_default(&cc))
	goto errout;

    /* fetch tgt directly from cache */
    retval = krb5_cc_retrieve_cred (cc,
				    KRB5_TC_MATCH_SRV_NAMEONLY,
				    &creds,
				    &tgt);
    krb5_cc_close(cc);
    if (retval)
	goto errout;

    /* tgt->client must be equal to creds.client */
    if (!krb5_principal_compare(tgt.client, creds.client)) {
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

    if (retval = krb5_send_tgs(kdcoptions, &creds.times, etype, sumtype,
			       tgt.server,
			       addrs,
			       creds.authdata,
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

	krb5_free_error(err_reply);
	goto errout;
    }
    
    if (retval = krb5_decode_kdc_rep(&tgsrep.response,
				     &tgt.keyblock,
				     etype, /* enctype */
				     &dec_rep))
	goto errout;
    
    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	goto errout;
    }
    
    /* now it's decrypted and ready for prime time */

    if (!krb5_principal_compare(dec_rep->client, tgt.client)) {
	retval = KRB5_KDCREP_MODIFIED;
	goto errout;
    }

    retval = mk_cred(dec_rep, etype, enc_key, 0, 0, outbuf);
    
errout:
    if (remote_host)
	free(remote_host);
    if (hrealms)
	krb5_xfree(hrealms);
    if (addrs)
	krb5_free_addresses(addrs);
    krb5_free_cred_contents(&creds);
    if (tgsrep.response.data)
	free(tgsrep.response.data);
    if (dec_rep)
	krb5_free_kdc_rep(dec_rep); 
    return retval;
}


/* Decode, decrypt and store the forwarded creds in the local ccache. */
krb5_error_code
rd_and_store_for_creds(inbuf, ticket, lusername)
     krb5_data *inbuf;
     krb5_ticket *ticket;
     char *lusername;
{
    krb5_encrypt_block eblock;
    krb5_creds creds;
    krb5_error_code retval;
    char ccname[35];
    krb5_ccache ccache = NULL;
    struct passwd *pwd;

    if (retval = rd_cred(inbuf, ticket->enc_part2->session, 
			 &creds, 0, 0)) {
	return(retval);
    }
    
    if (!(pwd = (struct passwd *) getpwnam(lusername))) {
	return -1;
    }

    /* Set the KRB5CCNAME ENV variable to keep sessions 
     * seperate. Use the process id of this process which is 
     * the rlogind or rshd. Set the environment variable as well.
     */
  
    sprintf(ccname, "FILE:/tmp/krb5cc_p%d", getpid());
    setenv("KRB5CCNAME", ccname, 0);
  
    if (retval = krb5_cc_resolve(ccname, &ccache)) {
	return(retval);
    }

    if (retval = krb5_cc_initialize(ccache,
				    ticket->enc_part2->client)) {
	return(retval);
    }

    if (retval = krb5_cc_store_cred(ccache, &creds)) {
	return(retval);
    }

    if (retval = chown(ccname+5, pwd->pw_uid, -1)) {
	return(retval);
    }

    return retval;
}

#endif /* KERBEROS */
