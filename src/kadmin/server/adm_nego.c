/*
 * kadmin/server/adm_nego.c
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
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 * 
 * Modify the Kerberos Database
 */


#include <com_err.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif

#include <stdio.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/asn1.h>

#include <krb5/adm_defs.h>
#include <krb5/kdb.h>
#include "adm_extern.h"

krb5_error_code
adm_negotiate_key(context, prog, client_creds, new_passwd)
    krb5_context context;
    char const * prog;
    krb5_ticket * client_creds;
    char * new_passwd;
{
   krb5_data msg_data, inbuf;
   krb5_error_code retval;
#if defined(MACH_PASS) || defined(SANDIA) /* Machine-generated passwords. */
   krb5_pwd_data *pwd_data;
   krb5_pwd_data encodable_data;
   krb5_data *encoded_pw_string;
   passwd_phrase_element **next_passwd_phrase_element;
   char *tmp_passwd, *tmp_phrase;
   krb5_authenticator *client_auth_data;
   int count, i, j, k;
   int legit_passwd = 0;
#endif
   extern int errno;

#if defined(MACH_PASS) || defined(SANDIA) /* Machine-generated passwords. */

#define clear_encodable_data() \
{ encodable_data.sequence_count = 0; \
  encodable_data.element = 0; \
}

#define free_seq_list() \
{ free(encodable_data.element); \
}

#define free_pwd_and_phrase_structures() \
{ next_passwd_phrase_element = encodable_data.element; \
  for (k = 0; \
       *next_passwd_phrase_element != 0 &&  k < encodable_data.sequence_count; \
       k++) { \
     free(*next_passwd_phrase_element); \
     *next_passwd_phrase_element = 0; \
     next_passwd_phrase_element++; } \
}

#define free_passwds() \
{ next_passwd_phrase_element = encodable_data.element; \
  for (k = 0; \
       *next_passwd_phrase_element != 0 && k < encodable_data.sequence_count; \
       k++) { \
     memset((char *) (*next_passwd_phrase_element)->passwd->data, \
	0, (*next_passwd_phrase_element)->passwd->length); \
     free((*next_passwd_phrase_element)->passwd->data); \
     next_passwd_phrase_element++; } \
}

#define free_phrases() \
{ next_passwd_phrase_element = encodable_data.element; \
  for (k = 0; \
       *next_passwd_phrase_element != 0 && k < encodable_data.sequence_count; \
       k++) { \
     memset((char *) (*next_passwd_phrase_element)->phrase->data, \
	0, (*next_passwd_phrase_element)->phrase->length); \
     free((*next_passwd_phrase_element)->phrase->data); \
     next_passwd_phrase_element++; } \
}

   encodable_data.sequence_count = 
		ADM_MAX_PW_CHOICES * ADM_MAX_PW_ITERATIONS;

	    /* Allocate List of Password and Phrase Addresses Pointers */
   if ((encodable_data.element = (passwd_phrase_element **) calloc(
		    encodable_data.sequence_count + 1, 
		    sizeof(passwd_phrase_element *))) == 
			(passwd_phrase_element **) 0) {
		clear_encodable_data();
		com_err("adm_negotiate_key", 0, 
			"No Memory for Password and Phrase List");
		return(1);
	}

   next_passwd_phrase_element = encodable_data.element;

	/* Allow for ADM_MAX_PW_ITERATIONS Sets of Five Passwords/Phrases */
   for ( i = 0; i < ADM_MAX_PW_ITERATIONS; i++) {
	if ( i == ADM_MAX_PW_ITERATIONS ) {
		com_err("adm_negotiate_key", 0, 
			"Excessive Password List Requests");
		return(1);
	}

		/* Allocate passwd_phrase_element structures */
        for (j = 0; j < ADM_MAX_PW_CHOICES; j++) {
	    if ((*next_passwd_phrase_element = 
		    (passwd_phrase_element *) calloc(1, 
		    sizeof(passwd_phrase_element))) == 
				(passwd_phrase_element *) 0) {
		free_pwd_and_phrase_structures();
		free_seq_list();
		clear_encodable_data();
		com_err("adm_negotiate_key", 0, 
		    "No Memory for Additional Password and Phrase Structures");
		return(1);
	    }

	    if ((retval = get_pwd_and_phrase("adm_negotiate_key",
			&tmp_passwd, &tmp_phrase))) {
		free_pwd_and_phrase_structures();
		free_seq_list();
		clear_encodable_data();
		com_err("adm_negotiate_key", 0, "Unable to get_pwd_and_phrase");
		return(1);
	    }

	    if (((*next_passwd_phrase_element)->passwd = 
		    (krb5_data *) calloc(1, 
		    sizeof(krb5_data))) == (krb5_data *) 0) {
		free_pwd_and_phrase_structures();
		free_seq_list();
		clear_encodable_data();
		com_err("adm_negotiate_key", 0, 
		    "No Memory for Additional Password and Phrase Structures");
		return(1);
	    }

	    if (((*next_passwd_phrase_element)->passwd->data = 
			(char *) calloc (1, 
			strlen(tmp_passwd))) == (char *) 0) {
		free_pwd_and_phrase_structures();
		free_seq_list();
		clear_encodable_data();
		com_err("adm_negotiate_key", ENOMEM, 
			"for Additional Passwords");
	    }

	    strcpy((*next_passwd_phrase_element)->passwd->data, tmp_passwd);
	    (*next_passwd_phrase_element)->passwd->length = strlen(tmp_passwd);

	    if (((*next_passwd_phrase_element)->phrase = 
		    (krb5_data *) calloc(1, 
		    sizeof(krb5_data))) == (krb5_data *) 0) {
		free_pwd_and_phrase_structures();
		free_seq_list();
		clear_encodable_data();
		com_err("adm_negotiate_key", 0, 
		    "No Memory for Additional Password and Phrase Structures");
		return(1);
	    }

	    if (((*next_passwd_phrase_element)->phrase->data = 
			(char *) calloc (1, 
			strlen(tmp_phrase))) == (char *) 0) {
		free_pwd_and_phrase_structures();
		free_seq_list();
		clear_encodable_data();
		com_err("adm_negotiate_key", ENOMEM, 
			"for Additional Passwords");
		return(1);
	    }

	    strcpy((*next_passwd_phrase_element)->phrase->data, tmp_phrase);
	    (*next_passwd_phrase_element)->phrase->length = strlen(tmp_phrase);

	    free(tmp_passwd);
	    free(tmp_phrase);

	    next_passwd_phrase_element++;
	}
    }	/* for i <= KADM_MAX_PW_CHOICES */

		/* Asn.1 Encode the Passwords and Phrases */
    if ((retval = encode_krb5_pwd_data(&encodable_data, 
			&encoded_pw_string))) {
	com_err("adm_negotiate_key", 0, 
			"Unable to encode Password and Phrase Data");
	return(1);
    }

		/* Free Phrases But Hold onto Passwds for Awhile*/
    free_phrases();

		/* Encrypt Password/Phrases Encoding */
    retval = krb5_mk_priv(context, encoded_pw_string,
			ETYPE_DES_CBC_CRC,
			client_creds->enc_part2->session, 
			&client_server_info.server_addr, 
			&client_server_info.client_addr,
			send_seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data);
    if (retval ) {
	free_passwds();
	free_pwd_and_phrase_structures();
	free_seq_list();
	clear_encodable_data();
	com_err("adm_negotiate_key", retval, "during mk_priv");
	return(1);  
    }

	/* Send Encrypted/Encoded Passwords and Phrases to Client */
    if (krb5_write_message(context, &client_server_info.client_socket, &msg_data)){
	free(msg_data.data);
	free_passwds();
	free_pwd_and_phrase_structures();
	free_seq_list();
	clear_encodable_data();
	com_err("adm_negotiate_key", 0, "Error Performing Password Write");
	return(1);  
    } 
    free(msg_data.data);

#endif /* MACH_PASS - Machine-gen. passwords */
		/* Read Client Response */
    if (krb5_read_message(context, &client_server_info.client_socket, &inbuf)){
#if defined(MACH_PASS) || defined(SANDIA)
	free_passwds();
	free_pwd_and_phrase_structures();
	free_seq_list();
	clear_encodable_data();
#endif
	com_err("adm_negotiate_key", errno, "Error Performing Password Read");
	return(1);
    }

		/* Decrypt Client Response */
    if ((retval = krb5_rd_priv(context, &inbuf,
			client_creds->enc_part2->session,
			&client_server_info.client_addr,
			&client_server_info.server_addr, 
			recv_seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data))) {
	free(inbuf.data);
#if defined(MACH_PASS) || defined(SANDIA)
	free_passwds();
	free_pwd_and_phrase_structures();
	free_seq_list();
	clear_encodable_data();
#endif
	com_err("adm_negotiate_key", retval, "krb5_rd_priv error %s",
				error_message(retval));
	return(1);
    }
    free(inbuf.data);

#if defined(MACH_PASS) || defined(SANDIA) /* Machine-generated passwords */
    legit_passwd = 0;
    next_passwd_phrase_element = encodable_data.element;
		/* Compare Response with Acceptable Passwords */
    for (j = 0; 
	j < ADM_MAX_PW_CHOICES * ADM_MAX_PW_ITERATIONS; 
	j++) {
	if ((retval = memcmp(msg_data.data, 
		   (*next_passwd_phrase_element)->passwd->data, 
		   strlen((*next_passwd_phrase_element)->passwd->data))) == 0) {
	    legit_passwd++;
	    break; /* Exit Loop - Match Found */
	}
	next_passwd_phrase_element++;
    }
		/* Now Free Passwds */
    free_passwds();

	/* free password_and_phrase structures */
    free_pwd_and_phrase_structures();

	/* free passwd_phrase_element list */
    free_seq_list();

	/* clear krb5_pwd_data */
    clear_encodable_data();

    if (!(legit_passwd)) {
	com_err("adm_negotiate_key", 0, "Invalid Password Entered");
	return(1);
    }
#endif
    strncpy(new_passwd, msg_data.data, msg_data.length);
    free(msg_data.data);

    return(0);
}

