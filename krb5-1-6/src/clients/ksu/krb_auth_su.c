/* 
 * Copyright (c) 1994 by the University of Southern California
 *
 * EXPORT OF THIS SOFTWARE from the United States of America may
 *     require a specific license from the United States Government.
 *     It is the responsibility of any person or organization contemplating
 *     export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to copy, modify, and distribute
 *     this software and its documentation in source and binary forms is
 *     hereby granted, provided that any documentation or other materials
 *     related to such distribution or use acknowledge that the software
 *     was developed by the University of Southern California. 
 *
 * DISCLAIMER OF WARRANTY.  THIS SOFTWARE IS PROVIDED "AS IS".  The
 *     University of Southern California MAKES NO REPRESENTATIONS OR
 *     WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not
 *     limitation, the University of Southern California MAKES NO
 *     REPRESENTATIONS OR WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY
 *     PARTICULAR PURPOSE. The University of Southern
 *     California shall not be held liable for any liability nor for any
 *     direct, indirect, or consequential damages with respect to any
 *     claim by the user or distributor of the ksu software.
 *
 * KSU was writen by:  Ari Medvinsky, ari@isi.edu
 */

#include "ksu.h"
    
static krb5_error_code krb5_verify_tkt_def
		  (krb5_context,
    		   krb5_principal,
    		   krb5_principal,
    		   krb5_keyblock *,
    		   krb5_data *,
    		   krb5_ticket **);

void plain_dump_principal ();

/*
 * Try no preauthentication first; then try the encrypted timestamp
 */
krb5_preauthtype * preauth_ptr = NULL;



krb5_boolean krb5_auth_check(context, client_pname, hostname, options,
			     target_user, cc, path_passwd, target_uid)
    krb5_context context;
    krb5_principal client_pname;
    char *hostname;
    opt_info *options;
    char *target_user;
    uid_t target_uid;
    krb5_ccache cc;
    int *path_passwd;
{
    krb5_principal client, server;
    krb5_creds tgt, tgtq, in_creds, * out_creds;
    krb5_creds **tgts = NULL; /* list of ticket granting tickets */       
    
    krb5_ticket * target_tkt; /* decrypted ticket for server */                
    krb5_error_code retval =0;
    int got_it = 0; 
    krb5_boolean zero_password;
    
    *path_passwd = 0;
    memset((char *) &tgtq, 0, sizeof(tgtq)); 
    memset((char *) &tgt, 0, sizeof(tgt)); 
    memset((char *) &in_creds, 0, sizeof(krb5_creds)); 
    
	
    if ((retval= krb5_copy_principal(context,  client_pname, &client))){
	com_err(prog_name, retval,"while copying client principal");   
	return (FALSE) ; 	
    }
    
    if (auth_debug) {
	dump_principal(context, "krb5_auth_check: Client principal name", 
		       client); 
    }
    
    if ((retval = krb5_sname_to_principal(context, hostname, NULL,
					  KRB5_NT_SRV_HST, &server))){
	com_err(prog_name, retval, 
		"while creating server %s principal name", hostname);  
	krb5_free_principal(context, client);
	return (FALSE) ; 	
    }
    
    if (auth_debug) {
	dump_principal(context, "krb5_auth_check: Server principal name", 
		       server); 
    }
    
    
    
    /* check if ticket is already in the cache, if it is
       then use it.    
       */
    if( krb5_fast_auth(context, client, server, target_user, cc) == TRUE){
	if (auth_debug ){ 	
	    fprintf (stderr,"Authenticated via fast_auth \n");
	}
	return TRUE;
    }
    
    /* check to see if the local tgt is in the cache */         
    
    if ((retval= krb5_copy_principal(context,  client, &tgtq.client))){
	com_err(prog_name, retval,"while copying client principal");   
	return (FALSE) ; 	
    }
    
    if ((retval = ksu_tgtname(context,  krb5_princ_realm(context, client),
			       krb5_princ_realm(context, client),
			       &tgtq.server))){ 		
	com_err(prog_name, retval, "while creating tgt for local realm");  
	krb5_free_principal(context, client);
	krb5_free_principal(context, server);
	return (FALSE) ; 	
    }	

    if (auth_debug){ dump_principal(context, "local tgt principal name", tgtq.server ); } 	
    retval = krb5_cc_retrieve_cred(context, cc,
				   KRB5_TC_MATCH_SRV_NAMEONLY | KRB5_TC_SUPPORTED_KTYPES,
				   &tgtq, &tgt); 
    
    if (! retval) retval = krb5_check_exp(context, tgt.times);
    
    if (retval){	
	if ((retval != KRB5_CC_NOTFOUND) &&  
	    (retval != KRB5KRB_AP_ERR_TKT_EXPIRED)){
	    com_err(prog_name, retval, 
		    "while retrieving creds from cache");
	    return (FALSE) ; 	
	}
    } else{
	got_it = 1;	
    }
    
    if (! got_it){
	
#ifdef GET_TGT_VIA_PASSWD
	if (krb5_seteuid(0)||krb5_seteuid(target_uid)) {
	    com_err("ksu", errno, "while switching to target uid");
	    return FALSE;
	}
	

	fprintf(stderr,"WARNING: Your password may be exposed if you enter it here and are logged \n");
	fprintf(stderr,"         in remotely using an unsecure (non-encrypted) channel. \n");
	
	/*get the ticket granting ticket, via passwd(promt for passwd)*/
	if (krb5_get_tkt_via_passwd (context, &cc, client, tgtq.server,
				     options, & zero_password) == FALSE){ 
	    krb5_seteuid(0);
	    
	    return FALSE;
	}
	*path_passwd = 1;
	if (krb5_seteuid(0)) {
	    com_err("ksu", errno, "while reclaiming root uid");
	    return FALSE;
	}
	
#else
	plain_dump_principal (context, client);
	fprintf(stderr,"does not have any appropriate tickets in the cache.\n");
	return FALSE;
	
#endif /* GET_TGT_VIA_PASSWD */ 

    }
    
    if ((retval= krb5_copy_principal(context, client, &in_creds.client))){
	com_err(prog_name, retval,"while copying client principal");   
	return (FALSE) ; 	
    }
    
    if ((retval= krb5_copy_principal(context, server, &in_creds.server))){
	com_err(prog_name, retval,"while copying client principal");   
	return (FALSE) ; 	
    }
    
    if ((retval = krb5_get_cred_from_kdc(context, cc, &in_creds, 
					 &out_creds, &tgts))){
	com_err(prog_name, retval, "while geting credentials from kdc");  
	return (FALSE);
    }
    

    if (auth_debug){ 
	fprintf(stderr,"krb5_auth_check: got ticket for end server \n"); 
	dump_principal(context, "out_creds->server", out_creds->server ); 
    } 	
    
    
    if (tgts){   
	register int i =0;
	
	if (auth_debug){	
	    fprintf(stderr, "krb5_auth_check: went via multiple realms");
	}
	while (tgts[i]){
	    if ((retval=krb5_cc_store_cred(context,cc,tgts[i]))) {
		com_err(prog_name, retval,
			"while storing credentials from cross-realm walk");
		return (FALSE);
	    }
	    i++;
	}
	krb5_free_tgt_creds(context, tgts);
    }
    
    retval = krb5_verify_tkt_def(context, client, server, 
				 &out_creds->keyblock, &out_creds->ticket,
				 &target_tkt);
    if (retval) {
	com_err(prog_name, retval, "while verifying ticket for server");
	return (FALSE);
    }
    
    if ((retval = krb5_cc_store_cred(context,  cc, out_creds))){
	com_err(prog_name, retval,
		"While storing credentials");
	return (FALSE);
    }

    return (TRUE);
}

/* krb5_fast_auth checks if ticket for the end server is already in
   the cache, if it is, we don't need a tgt */     

krb5_boolean krb5_fast_auth(context, client, server, target_user, cc)
    krb5_context context;
    krb5_principal client;
    krb5_principal server;
    char *target_user;
    krb5_ccache cc;
{
				 
    krb5_creds tgt, tgtq;
    krb5_ticket * target_tkt;                 
    krb5_error_code retval;
    
    memset((char *) &tgtq, 0, sizeof(tgtq)); 
    memset((char *) &tgt, 0, sizeof(tgt)); 
    
    if ((retval= krb5_copy_principal(context, client, &tgtq.client))){
	com_err(prog_name, retval,"while copying client principal");   
	return (FALSE) ; 	
    }
    
    if ((retval= krb5_copy_principal(context, server, &tgtq.server))){
	com_err(prog_name, retval,"while copying client principal");   
	return (FALSE) ; 	
    }
    
    if ((retval = krb5_cc_retrieve_cred(context, cc,
					KRB5_TC_MATCH_SRV_NAMEONLY | KRB5_TC_SUPPORTED_KTYPES,
					&tgtq, &tgt))){ 
	if (auth_debug)
	    com_err(prog_name, retval,"While Retrieving credentials"); 
	return (FALSE) ; 	
	
    }
    
    if ((retval = krb5_verify_tkt_def(context, client, server, &tgt.keyblock, 
				      &tgt.ticket, &target_tkt))){
	com_err(prog_name, retval, "while verifing ticket for server"); 
	return (FALSE);
    }
    
    return TRUE;
}

static krb5_error_code 
krb5_verify_tkt_def(context, client, server, cred_ses_key, 
		    scr_ticket, clear_ticket)
    /* IN */
    krb5_context context;
    krb5_principal client;
    krb5_principal server;
    krb5_keyblock *cred_ses_key;
    krb5_data *scr_ticket;
    /* OUT */
    krb5_ticket **clear_ticket;
{
    krb5_keytab keytabid;
    krb5_enctype enctype;
    krb5_keytab_entry ktentry;
    krb5_keyblock *tkt_key = NULL;
    krb5_ticket * tkt = NULL;
    krb5_error_code retval =0;
    krb5_keyblock *	tkt_ses_key;
    
    if ((retval = decode_krb5_ticket(scr_ticket, &tkt))){
	return retval;
    }
    
    if (server && !krb5_principal_compare(context, server, tkt->server)){
	return KRB5KRB_AP_WRONG_PRINC;
    }
    
    if (auth_debug){ 
	fprintf(stderr,"krb5_verify_tkt_def: verified target server\n");
	dump_principal(context, "server", server); 
	dump_principal(context, "tkt->server", tkt->server); 
    } 	
    
    /* get the default keytab */
    if ((retval = krb5_kt_default(context, &keytabid))){
	krb5_free_ticket(context, tkt);	
	return retval;
    }

    enctype = tkt->enc_part.enctype;
    
    if ((retval = krb5_kt_get_entry(context, keytabid, server,
				    tkt->enc_part.kvno, enctype, &ktentry))){
	krb5_free_ticket(context, tkt);	
	return retval;
    }
    
    krb5_kt_close(context, keytabid);
    
    if ((retval = krb5_copy_keyblock(context, &ktentry.key, &tkt_key))){
	krb5_free_ticket(context, tkt);	
	krb5_kt_free_entry(context, &ktentry);
	return retval;
    }
    
    /* decrypt the ticket */  
    if ((retval = krb5_decrypt_tkt_part(context, tkt_key, tkt))) {
	krb5_free_ticket(context, tkt);	
	krb5_kt_free_entry(context, &ktentry);
	krb5_free_keyblock(context, tkt_key);
	return(retval);
    }

    /* Check to make sure ticket hasn't expired */
    retval = krb5_check_exp(context, tkt->enc_part2->times);
    if (retval) {
	if (auth_debug && (retval == KRB5KRB_AP_ERR_TKT_EXPIRED)) {
	    fprintf(stderr,
		    "krb5_verify_tkt_def: ticket has expired");
	}
	krb5_free_ticket(context, tkt);	
	krb5_kt_free_entry(context, &ktentry);
	krb5_free_keyblock(context, tkt_key);
	return KRB5KRB_AP_ERR_TKT_EXPIRED;
    }
    
    if (!krb5_principal_compare(context, client, tkt->enc_part2->client)) {
	krb5_free_ticket(context, tkt);	
	krb5_kt_free_entry(context, &ktentry);
	krb5_free_keyblock(context, tkt_key);
	return KRB5KRB_AP_ERR_BADMATCH;
    }
    
    if (auth_debug){ 
	fprintf(stderr,
		"krb5_verify_tkt_def: verified client's identity\n");
	dump_principal(context, "client", client);
	dump_principal(context, "tkt->enc_part2->client",tkt->enc_part2->client);
    } 	
    
    tkt_ses_key = tkt->enc_part2->session;	
    
    if (cred_ses_key->enctype != tkt_ses_key->enctype ||
	cred_ses_key->length != tkt_ses_key->length ||
	memcmp((char *)cred_ses_key->contents,
	       (char *)tkt_ses_key->contents, cred_ses_key->length)) {
	
	krb5_free_ticket(context, tkt);	
	krb5_kt_free_entry(context, &ktentry);
	krb5_free_keyblock(context, tkt_key);
	return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }
    
    if (auth_debug){ 
	fprintf(stderr,
		"krb5_verify_tkt_def: session keys match \n");
    } 	
    
    *clear_ticket = tkt; 
    krb5_kt_free_entry(context, &ktentry);
    krb5_free_keyblock(context, tkt_key);
    return 0; 	
    
}


krb5_boolean krb5_get_tkt_via_passwd (context, ccache, client, server,
				      options, zero_password)
    krb5_context context;
    krb5_ccache *ccache;
    krb5_principal client;
    krb5_principal server;
    opt_info *options;
    krb5_boolean *zero_password;
{
    krb5_error_code code;
    krb5_creds my_creds;
    krb5_timestamp now;
    unsigned int pwsize;
    char password[255], *client_name, prompt[255];


    *zero_password = FALSE;	
    
    if ((code = krb5_unparse_name(context, client, &client_name))) {
        com_err (prog_name, code, "when unparsing name");
        return (FALSE);
    }

    memset((char *)&my_creds, 0, sizeof(my_creds));
    
    if ((code = krb5_copy_principal(context, client, &my_creds.client))){ 
        com_err (prog_name, code, "while copying principal");
	return (FALSE);	
    }	

    if ((code = krb5_copy_principal(context, server, &my_creds.server))){ 
        com_err (prog_name, code, "while copying principal");
	return (FALSE);	
    }	

    if ((code = krb5_timeofday(context, &now))) {
	com_err(prog_name, code, "while getting time of day");
	return (FALSE);	
    }

    my_creds.times.starttime = 0;	/* start timer when request
					   gets to KDC */
    
    my_creds.times.endtime = now + options->lifetime;
    if (options->opt & KDC_OPT_RENEWABLE) {
	my_creds.times.renew_till = now + options->rlife;
    } else
	my_creds.times.renew_till = 0;

    if (strlen (client_name) + 80 > sizeof (prompt)) {
	fprintf (stderr,
		 "principal name %s too long for internal buffer space\n",
		 client_name);
	return FALSE;
    }
    (void) sprintf(prompt,"Kerberos password for %s: ", client_name);
    
    pwsize = sizeof(password);
    
    code = krb5_read_password(context, prompt, 0, password, &pwsize);
    if (code ) {
	com_err(prog_name, code, "while reading password for '%s'\n",
		client_name);
	memset(password, 0, sizeof(password));
	return (FALSE); 
    }
    
    if ( pwsize == 0) {
	fprintf(stderr, "No password given\n");
	*zero_password = TRUE;
	memset(password, 0, sizeof(password));
	return (FALSE); 
    }
    
    code = krb5_get_in_tkt_with_password(context, options->opt, 
					 0, NULL, preauth_ptr,
					 password, *ccache, &my_creds, 0);
    memset(password, 0, sizeof(password));
    
    
    if (code) {
	if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
	    fprintf (stderr, "%s: Password incorrect\n", prog_name);
	else
	    com_err (prog_name, code, "while getting initial credentials");
	return (FALSE);
    }
    return (TRUE);
}


void dump_principal (context, str, p)
    krb5_context context;
    char *str;
    krb5_principal p;
{
    char * stname;
    krb5_error_code retval; 

    if ((retval = krb5_unparse_name(context, p, &stname))) {
	fprintf(stderr, " %s while unparsing name\n", error_message(retval));
    }
    fprintf(stderr, " %s: %s\n", str, stname);
}

void plain_dump_principal (context, p)
    krb5_context context;
    krb5_principal p;
{    
    char * stname;
    krb5_error_code retval; 

    if ((retval = krb5_unparse_name(context, p, &stname)))
	fprintf(stderr, " %s while unparsing name\n", error_message(retval));
    fprintf(stderr, "%s ", stname);
}


/**********************************************************************
returns the principal that is closest to client. plist contains
a principal list obtained from .k5login and parhaps .k5users file.   
This routine gets called before getting the password for a tgt.             
A principal is picked that has the best chance of getting in.          

**********************************************************************/


krb5_error_code get_best_principal(context, plist, client)
    krb5_context context;
    char **plist;
    krb5_principal *client;
{
    krb5_error_code retval =0; 
    krb5_principal temp_client, best_client = NULL;
    
    int i = 0, nelem;
    
    if (! plist ) return 0;
    
    nelem = krb5_princ_size(context, *client);
    
    while(plist[i]){
	
	if ((retval = krb5_parse_name(context, plist[i], &temp_client))){
	    return retval;
	}
	
	if (krb5_princ_realm(context, *client)->length ==
	    krb5_princ_realm(context, temp_client)->length  
	    && (!memcmp (krb5_princ_realm(context, *client)->data,
			 krb5_princ_realm(context, temp_client)->data,
			 krb5_princ_realm(context, temp_client)->length))){
	    
	    
	    if (nelem &&
		krb5_princ_size(context, *client) > 0 &&
		krb5_princ_size(context, temp_client) > 0) {
		krb5_data *p1 =
		    krb5_princ_component(context, *client, 0);
		krb5_data *p2 = 
		    krb5_princ_component(context, temp_client, 0);
		
		if ((p1->length == p2->length) &&
		    (!memcmp(p1->data,p2->data,p1->length))){
		    
		    if (auth_debug){
			fprintf(stderr,
				"get_best_principal: compare with %s\n",
				plist[i]);
		    }
		    
		    if(best_client){
			if(krb5_princ_size(context, best_client) >
			   krb5_princ_size(context, temp_client)){
			    best_client = temp_client;
			}
		    }else{
			best_client = temp_client;
		    }
		}
	    }
	    
	}
	i++;
    }
    
    if (best_client) *client = best_client;
    return 0;
}
