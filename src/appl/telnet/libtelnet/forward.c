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

#if defined(KERBEROS) || defined(KRB5)
#include <stdio.h>
#include <pwd.h>
#include <netdb.h>
 
#include "k5-int.h"
 
extern char *line;		/* see sys_term.c */

/* Decode, decrypt and store the forwarded creds in the local ccache. */
krb5_error_code
rd_and_store_for_creds(context, auth_context, inbuf, ticket, lusername)
    krb5_context context;
    krb5_auth_context auth_context;
    krb5_data *inbuf;
    krb5_ticket *ticket;
    char *lusername;
{
    krb5_creds **creds;
    krb5_error_code retval;
    char ccname[35];
    krb5_ccache ccache = NULL;
    struct passwd *pwd;

    if (!(pwd = (struct passwd *) getpwnam(lusername))) 
	return -1;

    if (retval = krb5_rd_cred(context, auth_context, inbuf, &creds, NULL)) 
	return(retval);

    if (*line) {
      /* code from appl/bsd/login.c since it will do the same */
      sprintf(ccname, "FILE:/tmp/krb5cc_%s", strrchr(line, '/')+1);
    } else {
     /* since default will be based on uid and we haven't changed yet */
     sprintf(ccname, "FILE:/tmp/krb5cc_%d", pwd->pw_uid);
    }
    setenv(KRB5_ENV_CCNAME, ccname, 1);

    if (retval = krb5_cc_resolve(context, ccname, &ccache))
	goto cleanup;

    if (retval = krb5_cc_initialize(context, ccache, ticket->enc_part2->client))
	goto cleanup;

    if (retval = krb5_cc_store_cred(context, ccache, *creds)) 
	goto cleanup;

    if (retval = chown(ccname+5, pwd->pw_uid, -1)) 
	goto cleanup;

cleanup:
    krb5_free_creds(context, *creds);
    return retval;
}


#define KRB5_DEFAULT_LIFE 60*60*10   /* 10 hours */
/* helper function: convert flags to necessary KDC options */
#define flags2options(flags) (flags & KDC_TKT_COMMON_MASK)

/* Get a TGT for use at the remote host */
krb5_error_code INTERFACE
get_for_creds(context, auth_context, rhost, client, forwardable, outbuf)
    krb5_context context;
    krb5_auth_context auth_context;
    char *rhost;
    krb5_principal client;
    int forwardable;      /* Should forwarded TGT also be forwardable? */
    krb5_data *outbuf;
{
    krb5_replay_data replaydata;
    krb5_data * scratch;
    struct hostent *hp;
    krb5_address **addrs;
    krb5_error_code retval;
    krb5_error *err_reply;
    krb5_creds creds, tgt;
    krb5_creds *pcreds;
    krb5_ccache cc;
    krb5_flags kdcoptions;
    krb5_timestamp now;
    char *remote_host = 0;
    char **hrealms = 0;
    int i;

    memset((char *)&creds, 0, sizeof(creds));

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

    if (retval = krb5_get_cred_via_tkt(context, &tgt, kdcoptions,
                                       addrs, &creds, &pcreds))
        goto errout;

    retval = krb5_mk_1cred(context, auth_context, pcreds,
                           &scratch, &replaydata);
    krb5_free_creds(context, pcreds);
    *outbuf = *scratch;
    krb5_xfree(scratch);
        
errout:
    if (remote_host)
	free(remote_host);
    if (hrealms)
	krb5_xfree(hrealms);
    if (addrs)
	krb5_free_addresses(context, addrs);
    krb5_free_cred_contents(context, &creds);
    return retval;
}

#endif /* defined(KRB5) && defined(FORWARD) */
