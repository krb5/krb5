/*
 * appl/telnet/libtelnet/forward.c
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

#if defined(KRB5) && defined(FORWARD)
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
    krb5_kdc_rep *dec_rep;
    krb5_error *err_reply;
    krb5_response tgsrep;
    krb5_creds creds, tgt;
    krb5_ccache cc;
    krb5_flags kdcoptions;
    krb5_timestamp now;
    char *remote_host;
    char **hrealms;
    int i;

    if (!rhost || !(hp = gethostbyname(rhost)))
      return KRB5_ERR_BAD_HOSTNAME;

    remote_host = (char *) malloc(strlen(hp->h_name)+1);
    if (!remote_host)
      return ENOMEM;
    strcpy(remote_host, hp->h_name);

    if (retval = krb5_get_host_realm(remote_host, &hrealms)) {
	free(remote_host);
	return retval;
    }
    if (!hrealms[0]) {
	free(remote_host);
	krb5_xfree(hrealms);
	return KRB5_ERR_HOST_REALM_UNKNOWN;
    }

    /* Count elements */
    for(i=0; hp->h_addr_list[i]; i++);

    addrs = (krb5_address **) malloc ((i+1)*sizeof(*addrs));
    if (!addrs)
      return ENOMEM;
    
    for(i=0; hp->h_addr_list[i]; i++) {
	addrs[i] = (krb5_address *) malloc(sizeof(krb5_address));
	if (addrs[i]) {
	    addrs[i]->addrtype = hp->h_addrtype;
	    addrs[i]->length   = hp->h_length;
	    addrs[i]->contents = (unsigned char *)malloc(addrs[i]->length);
	    if (!addrs[i]->contents) {
		krb5_free_addresses(addrs);
		return ENOMEM;
	    }
	    else
	      memcpy ((char *)addrs[i]->contents, hp->h_addr_list[i],
		      addrs[i]->length);
	}
	else {
	    return ENOMEM;
	}
    }
    addrs[i] = 0;

    memset((char *)&creds, 0, sizeof(creds));
    if (retval = krb5_copy_principal(client, &creds.client))
      return retval;
    
    if (retval = krb5_build_principal_ext(&creds.server,
					  strlen(hrealms[0]),
					  hrealms[0],
					  KRB5_TGS_NAME_SIZE,
					  KRB5_TGS_NAME,
					  client->realm.length,
					  client->realm.data,
					  0))
      return retval;
	
    creds.times.starttime = 0;
    if (retval = krb5_timeofday(&now)) {
	return retval;
    }
    creds.times.endtime = now + KRB5_DEFAULT_LIFE;
    creds.times.renew_till = 0;
    
    if (retval = krb5_cc_default(&cc)) {
	return retval;
    }

    /* fetch tgt directly from cache */
    if (retval = krb5_cc_retrieve_cred (cc,
					KRB5_TC_MATCH_SRV_NAMEONLY,
					&creds,
					&tgt)) {
	return retval;
    }

    /* tgt->client must be equal to creds.client */
    if (!krb5_principal_compare(tgt.client, creds.client))
	return KRB5_PRINC_NOMATCH;

    if (!tgt.ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    kdcoptions = flags2options(tgt.ticket_flags)|KDC_OPT_FORWARDED;

    if (!forwardable) /* Reset KDC_OPT_FORWARDABLE */
      kdcoptions &= ~(KDC_OPT_FORWARDABLE);

    if (retval = krb5_send_tgs(kdcoptions, &creds.times, etype, sumtype,
			       creds.server,
			       addrs,
			       creds.authdata,
			       0,		/* no padata */
			       0,		/* no second ticket */
			       &tgt, &tgsrep))
	return retval;

#undef cleanup
#define cleanup() free(tgsrep.response.data)

    switch (tgsrep.message_type) {
    case KRB5_TGS_REP:
	break;
    case KRB5_ERROR:
    default:
	if (!krb5_is_krb_error(&tgsrep.response)) {
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;
	} else
	    retval = decode_krb5_error(&tgsrep.response, &err_reply);
	if (retval) {
	    cleanup();
	    return retval;		/* neither proper reply nor error! */
	}

	retval = err_reply->error + ERROR_TABLE_BASE_krb5;

	krb5_free_error(err_reply);
	cleanup();
	return retval;
    }
    retval = krb5_decode_kdc_rep(&tgsrep.response,
				 &tgt.keyblock,
				 etype, /* enctype */
				 &dec_rep);
    
    cleanup();
    if (retval)
	return retval;
#undef cleanup
#define cleanup() {\
	memset((char *)dec_rep->enc_part2->session->contents, 0,\
	      dec_rep->enc_part2->session->length);\
		  krb5_free_kdc_rep(dec_rep); }

    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	cleanup();
	return retval;
    }
    
    /* now it's decrypted and ready for prime time */

    if (!krb5_principal_compare(dec_rep->client, tgt.client)) {
	cleanup();
	return KRB5_KDCREP_MODIFIED;
    }

    if (retval = mk_cred(dec_rep, 
			 etype, 
			 enc_key,
			 0,
			 0, 
			 outbuf))
      return retval;

    krb5_free_kdc_rep(dec_rep);

    return retval;
#undef cleanup
}

/* Decode, decrypt and store the forwarded creds in the local ccache. */
krb5_error_code
rd_and_store_for_creds(inbuf, ticket, lusername)
     krb5_data *inbuf;
     krb5_ticket *ticket;
     char *lusername;
{
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

    sprintf(ccname, "FILE:/tmp/krb5cc_%d", pwd->pw_uid);

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

#endif /* defined(KRB5) && defined(FORWARD) */
