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
    
void plain_dump_principal ();

krb5_data tgtname = {
    KRB5_TGS_NAME_SIZE,
    KRB5_TGS_NAME
};

/*
 * Try no preauthentication first; then try the encrypted timestamp
 */
int preauth_search_list[] = {
	0,			
	KRB5_PADATA_ENC_TIMESTAMP,
	-1
	};



krb5_boolean krb5_auth_check(krb5_principal client_pname, 
			     char * hostname, opt_info * options, 
			     char * target_user, krb5_ccache cc, 
			     int * path_passwd)
{
krb5_principal client, server, temp_client; 
krb5_creds tgt, tgtq, cred;
krb5_creds **tgts = NULL; /* list of ticket granting tickets */       

krb5_ticket * target_tkt; /* decrypted ticket for server */                
int default_client = 1 ; 
struct passwd *pw = NULL;
krb5_error_code retval =0;
char ** k5login_plist = NULL;
int got_it = 0; 
char * client_name;		


	*path_passwd = 0;
	memset((char *) &tgtq, 0, sizeof(tgtq)); 
	memset((char *) &tgt, 0, sizeof(tgt)); 
	memset((char *) &cred, 0, sizeof(cred)); 

	
	if (retval= krb5_copy_principal( client_pname, &client)){
		com_err(prog_name, retval,"while copying client principal");   
 		return (FALSE) ; 	
	}

	if (auth_debug)
	{ dump_principal("krb5_auth_check: Client principal name", client); } 	

	if ( retval = krb5_sname_to_principal(hostname, NULL,
					      KRB5_NT_SRV_HST, &server)){
			com_err(prog_name, retval, 
				"while creating server %s principal name", hostname);  
			krb5_free_principal(client);
 			return (FALSE) ; 	
	}

	if (auth_debug)
	{ dump_principal("krb5_auth_check: Server principal name", server); } 



	/* check if ticket is already in the cache, if it is
	   then use it.    
	*/
       if( krb5_fast_auth(client, server, target_user, cc) == TRUE){
	  	if (auth_debug ){ 	
			fprintf (stderr,"Athenticated via fast_auth \n");
		}
		return TRUE;
        }

	/* check to see if the local tgt is in the cache */         

	if (retval= krb5_copy_principal( client, &tgtq.client)){
		com_err(prog_name, retval,"while copying client principal");   
 		return (FALSE) ; 	
	}

	if (retval = krb5_tgtname( krb5_princ_realm (client), krb5_princ_realm(client),
				&tgtq.server)){ 		
		com_err(prog_name, retval, "while creating tgt for local realm");  
		krb5_free_principal(client);
		krb5_free_principal(server);
 		return (FALSE) ; 	
	}	

	if (auth_debug){ dump_principal("local tgt principal name", tgtq.server ); } 	
	retval = krb5_cc_retrieve_cred(cc, KRB5_TC_MATCH_SRV_NAMEONLY,
					&tgtq, &tgt); 

	if (! retval) retval = krb5_check_exp(tgt.times);

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

		fprintf(stderr,"WARNING: Your password may get exposed if you are logged in remotely \n");
		fprintf(stderr,"         and don't have a secure channel. \n");
	
		/*get the ticket granting ticket, via passwd(promt for passwd)*/
	 	if (krb5_get_tkt_via_passwd (&cc, client, tgtq.server,
				       options) == FALSE){ 
				return FALSE;
		}
		*path_passwd = 1;
#else
	plain_dump_principal (client);
	fprintf(stderr,"does not have any appropriate tickets in the cache.\n");
	return FALSE;

#endif /* GET_TGT_VIA_PASSWD */ 

	}

	if (retval= krb5_copy_principal( client, &cred.client)){
		com_err(prog_name, retval,"while copying client principal");   
 		return (FALSE) ; 	
	}

	if (retval= krb5_copy_principal( server, &cred.server)){
		com_err(prog_name, retval,"while copying client principal");   
 		return (FALSE) ; 	
	}
	
	if (retval = krb5_get_cred_from_kdc(cc, &cred, &tgts)){
		com_err(prog_name, retval, "while geting credentials from kdc");  
		return (FALSE);
	}


	if (auth_debug){ 
	 	fprintf(stderr,"krb5_auth_check: got ticket for end server \n"); 
		dump_principal("cred.server", cred.server ); 
	} 	


	if (tgts){   
		register int i =0;

		if (auth_debug){	
		   fprintf(stderr, "krb5_auth_check: went via multiple realms");
		}
		while (tgts[i]){
			if (retval = krb5_cc_store_cred( cc, tgts[i])){
		 	     com_err(prog_name, retval,
			     "while storing credentials from cross-realm walk");
			     return (FALSE);
			}
			i++;
		}
		krb5_free_tgt_creds(tgts);
	}

	if (retval = krb5_verify_tkt_def(client, server, 
					&cred.ticket, &target_tkt)){
		com_err(prog_name, retval, "while verifing ticket for server"); 
		return (FALSE);
	}

	if (retval = krb5_cc_store_cred( cc, &cred)){
		com_err(prog_name, retval,
		        "While storing credentials");
		return (FALSE);
	}

	return (TRUE);
}

/* krb5_fast_auth checks if ticket for the end server is already in
   the cache, if it is, we don't need a tgt */     

krb5_boolean krb5_fast_auth(krb5_principal client, krb5_principal server, 
			    char * target_user, krb5_ccache cc){
				 
krb5_creds tgt, tgtq;
krb5_ticket * target_tkt;                 
krb5_error_code retval;
char * client_name; 

	memset((char *) &tgtq, 0, sizeof(tgtq)); 
	memset((char *) &tgt, 0, sizeof(tgt)); 

	if (retval= krb5_copy_principal( client, &tgtq.client)){
		com_err(prog_name, retval,"while copying client principal");   
 		return (FALSE) ; 	
	}

	if (retval= krb5_copy_principal( server, &tgtq.server)){
		com_err(prog_name, retval,"while copying client principal");   
 		return (FALSE) ; 	
	}

	if (retval = krb5_cc_retrieve_cred(cc, KRB5_TC_MATCH_SRV_NAMEONLY,
					&tgtq, &tgt)){ 
		if (auth_debug)
		   com_err(prog_name, retval,"While Retrieving credentials"); 
 		return (FALSE) ; 	

	}

	if (retval = krb5_verify_tkt_def(client, server, 
					&tgt.ticket, &target_tkt)){
		com_err(prog_name, retval, "while verifing ticket for server"); 
		return (FALSE);
	}

	return TRUE;
}



krb5_error_code krb5_verify_tkt_def( /* IN */ 
				   krb5_principal client,
				   krb5_principal server, krb5_data * scr_ticket,
				   /* OUT */	 
				   krb5_ticket ** clear_ticket)
{
krb5_keytab keytabid;
krb5_keytab_entry ktentry;
krb5_keyblock *tkt_key = NULL;
krb5_ticket * tkt = NULL;
krb5_error_code retval =0;

	if (retval = decode_krb5_ticket(scr_ticket, &tkt)){
		return retval;
	}

	if (server && !krb5_principal_compare(server, tkt->server)){
		return KRB5KRB_AP_WRONG_PRINC;
	}

	if (auth_debug){ 
	    fprintf(stderr,"krb5_verify_tkt_def: verified target server\n");
	    dump_principal("server", server); 
	    dump_principal("tkt->server", tkt->server); 
	} 	

	/* get the default keytab */
	if( retval = krb5_kt_default(&keytabid)){
		krb5_free_ticket(tkt);	
		return retval;
	}

	if (retval = krb5_kt_get_entry(keytabid, server,
					 tkt->enc_part.kvno, &ktentry)){
		krb5_free_ticket(tkt);	
		return retval;
	}

	krb5_kt_close(keytabid);

 	if ( retval = krb5_copy_keyblock(&ktentry.key, &tkt_key)){
		krb5_free_ticket(tkt);	
		krb5_kt_free_entry(&ktentry);
		return retval;
 	}

    /* decrypt the ticket */  
	if (retval = krb5_decrypt_tkt_part(tkt_key, tkt)) {
		krb5_free_ticket(tkt);	
		krb5_kt_free_entry(&ktentry);
		krb5_free_keyblock(tkt_key);
		return(retval);
	}

	if (!krb5_principal_compare(client, tkt->enc_part2->client)) {
			retval = KRB5KRB_AP_ERR_BADMATCH;
	}

	if (auth_debug){ 
	 	fprintf(stderr,
		       "krb5_verify_tkt_def: verified client's identity\n");
	    	dump_principal("client", client);
	    	dump_principal("tkt->enc_part2->client",tkt->enc_part2->client);
	} 	

	*clear_ticket = tkt; 
	krb5_kt_free_entry(&ktentry);
	krb5_free_keyblock(tkt_key);
    return retval; 	

}


krb5_boolean krb5_get_tkt_via_passwd (krb5_ccache * ccache, krb5_principal client,
				    krb5_principal server, opt_info * options) { 
    krb5_address **my_addresses;
    krb5_error_code code;
    krb5_creds my_creds;
    krb5_timestamp now;
    int preauth_type = -1;
    int pwsize;
    int	i;
    char password[255], *client_name, prompt[255];

    if (code = krb5_unparse_name(client, &client_name)) {
        com_err (prog_name, code, "when unparsing name");
        return (FALSE);
    }

    memset((char *)&my_creds, 0, sizeof(my_creds));
    
    if (code = krb5_copy_principal(client, &my_creds.client)){ 
        com_err (prog_name, code, "while copying principal");
	return (FALSE);	
    }	

    if (code = krb5_copy_principal(server, &my_creds.server)){ 
        com_err (prog_name, code, "while copying principal");
	return (FALSE);	
    }	

    code = krb5_os_localaddr(&my_addresses);

    if (code != 0) {
	com_err (prog_name, code, "when getting my address");
	return (FALSE);	
    }

    if (code = krb5_timeofday(&now)) {
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


	 (void) sprintf(prompt,"Kerberos password for %s: ", (char *) client_name);

	 pwsize = sizeof(password);

	 code = krb5_read_password(prompt, 0, password, &pwsize);
	 if (code || pwsize == 0) {
	      fprintf(stderr, "Error while reading password for '%s'\n",
		      client_name);
	      memset(password, 0, sizeof(password));
	      krb5_free_addresses(my_addresses);
	      return (FALSE); 
	 }

	 if (preauth_type > 0) {
	     code = krb5_get_in_tkt_with_password(options->opt, my_addresses,
						  preauth_type,
						  ETYPE_DES_CBC_CRC,
						  KEYTYPE_DES,
						  password,
						  *ccache,
						  &my_creds, 0);
	 } else {
	     for (i=0; preauth_search_list[i] >= 0; i++) {
		 code = krb5_get_in_tkt_with_password(options->opt, my_addresses,
						      preauth_search_list[i],
						      ETYPE_DES_CBC_CRC,
						      KEYTYPE_DES,
						      password,
						      *ccache,
						      &my_creds, 0);
	     if (code != KRB5KDC_PREAUTH_FAILED &&
		 code != KRB5KRB_ERR_GENERIC)
		 break;
	     }
	 }
	 memset(password, 0, sizeof(password));

    
    krb5_free_addresses(my_addresses);
    
    if (code) {
	if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
	    fprintf (stderr, "%s: Password incorrect\n", prog_name);
	else
	    com_err (prog_name, code, "while getting initial credentials");
	return (FALSE);
    }
    return (TRUE);
}


void dump_principal (char * str, krb5_principal p)
{    
char * stname;
krb5_error_code retval; 

		if (retval = krb5_unparse_name(p, &stname)){
			fprintf(stderr," %s while unparsing name \n",
				error_message(retval));    	
		}
		fprintf(stderr, " %s: %s\n", str, stname );
}

void plain_dump_principal ( krb5_principal p)
{    
char * stname;
krb5_error_code retval; 

		if (retval = krb5_unparse_name(p, &stname)){
			fprintf(stderr," %s while unparsing name \n",
				error_message(retval));    	
		}
		fprintf(stderr, "%s ",  stname );
}


static time_t convtime();

krb5_error_code
krb5_parse_lifetime (time, len)
    char *time;
    long *len;
{
    *len = convtime(time);
    return 0;
}
    

/*
 * this next function was lifted from the source to sendmail, which is:
 * 
 * Copyright (c) 1983 Eric P. Allman
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted provided
 * that: (1) source distributions retain this entire copyright notice and
 * comment, and (2) distributions including binaries display the following
 * acknowledgement:  ``This product includes software developed by the
 * University of California, Berkeley and its contributors'' in the
 * documentation or other materials provided with the distribution and in
 * all advertising materials mentioning features or use of this software.
 * Neither the name of the University nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <ctype.h>			/* for isdigit */

static time_t
convtime(p)
        char *p;
{
        register time_t t, r;
        register char c;

        r = 0;
        while (*p != '\0')
        {
                t = 0;
                while (isdigit(c = *p++))
                        t = t * 10 + (c - '0');
                if (c == '\0')
                        p--;
                switch (c)
                {
                  case 'w':             /* weeks */
                        t *= 7;

                  case 'd':             /* days */
                        t *= 24;

                  case 'h':             /* hours */
                  default:
                        t *= 60;

                  case 'm':             /* minutes */
                        t *= 60;

                  case 's':             /* seconds */
                        break;
                }
                r += t;
        }

        return (r);
}

krb5_error_code get_tgt_via_login_list(krb5_principal server, krb5_ccache cc,
		 char ** k5login_plist, krb5_principal * client, int * got_it){

krb5_creds tgt, tgtq;
int i =0;	
krb5_principal temp_client; 
krb5_error_code retval =0; 
	*got_it=0;

	if (! k5login_plist ) return 0;   

        memset((char *) &tgtq, 0, sizeof(tgtq));
	memset((char *) &tgt, 0, sizeof(tgt));

	while(k5login_plist[i]){
		if (retval = krb5_parse_name(k5login_plist[i],
                                                &temp_client)){
                         return retval;
                }


		if (retval= krb5_copy_principal( temp_client, &tgtq.client)){
 			return retval ; 	
		}

		/* check to see if the local tgt is in the cache */         

		if (retval = krb5_tgtname( krb5_princ_realm (temp_client),
			   krb5_princ_realm(temp_client), &tgtq.server)){ 	
 			return retval ; 	
		}

		retval = krb5_cc_retrieve_cred(cc, KRB5_TC_MATCH_SRV_NAMEONLY,
					&tgtq, &tgt); 

		if (! retval) retval = krb5_check_exp(tgt.times);

		if (retval){	
			if ((retval != KRB5_CC_NOTFOUND) &&  
       	        		  (retval != KRB5KRB_AP_ERR_TKT_EXPIRED)){
 				return retval ; 	
			}
		} else{
			if (auth_debug){		
				fprintf(stderr,"Auth via k5login name %s\n", 	
					k5login_plist[i]);
			}

			*got_it = 1;	
			*client = temp_client;
			break;
		}

	i++;
	}

	return 0;
}

/**********************************************************************
returns the principal that is closes to client. plist contains
a principal list obtained from .k5login and parhaps .k5users file.   
This routine gets called before getting the password for a tgt.             
A principal is picked that has the best chance of getting in.          

**********************************************************************/


krb5_error_code get_best_principal( char ** plist, krb5_principal * client)              
{
krb5_error_code retval =0; 
char * client_name;
krb5_principal temp_client, best_client = NULL;

int i = 0, nelem;

	if (! plist ) return 0;

	nelem = krb5_princ_size(*client);

        while(plist[i]){

		if (retval = krb5_parse_name(plist[i], &temp_client)){
                         return retval;
                }

		if (krb5_princ_realm(*client)->length ==
	   	    krb5_princ_realm(temp_client)->length  
       	    		 && (!memcmp (krb5_princ_realm(*client)->data,
	 			      krb5_princ_realm(temp_client)->data,
                	  	      krb5_princ_realm(temp_client)->length))){


			if(nelem){ 
				krb5_data *p1 =
					 krb5_princ_component(*client, 0);
        			krb5_data *p2 = 
					krb5_princ_component(temp_client, 0);

			        if ((p1->length == p2->length) &&
            			    (!memcmp(p1->data,p2->data,p1->length))){

					if (auth_debug){
				  	   fprintf(stderr,
					  "get_best_principal: compare with %s\n",
				 		plist[i]);
					}
					 				
					if(best_client){
						if(krb5_princ_size(best_client) >
					           krb5_princ_size(temp_client)){
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
