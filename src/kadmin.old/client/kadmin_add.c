/*
 * kadmin/client/kadmin_add.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 */

/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */


/*
 * kadmin_add
 * Perform Remote Kerberos Administrative Functions
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include "com_err.h"

#include <sys/param.h>

#include "k5-int.h"
#include "adm_defs.h"

void decode_kadmind_reply();
int print_status_message();

krb5_error_code
kadm_add_user(context, auth_context, my_creds, local_socket, 
	      oper_type, principal)
    krb5_context 	  context;
    krb5_auth_context	  auth_context;
    krb5_creds 		* my_creds;
    int 		* local_socket;
    int 		  oper_type;
    char 		* principal;
{
    krb5_data msg_data, inbuf;
    kadmin_requests rd_priv_resp;
    char username[255];
    char *password;
    int pwsize;
    int count;
    krb5_replay_data replaydata;
    krb5_error_code retval;     /* return code */
    
    if ((inbuf.data = (char *) calloc(1, 3 + sizeof(username))) == (char *) 0) {
        fprintf(stderr, "No memory for command!\n");
        return(1);
    }
    
    inbuf.data[0] = KADMIN;
    inbuf.data[1] = oper_type;
    inbuf.data[2] = SENDDATA2;
    
    if (principal && principal[0] != '\0')
	strcpy(username, principal);
    else {
	count = 0;
	do {
	    fprintf(stdout, "\nName of Principal to be Added: ");
	    fgets(username, sizeof(username), stdin);
	    if (username[0] == '\n')
		fprintf(stderr, "Invalid Principal name!\n");
	    count++;
	} while (username[0] == '\n' && count < 3);

	if (username[0] == '\n') {
	    fprintf(stderr, "Aborting!!\n\n");
	    return(1);
	}

	username[strlen(username) -1] = '\0';
    }
    
    (void) memcpy( inbuf.data + 3, username, strlen(username));
    inbuf.length = strlen(username) + 3;
    
    if ((retval = krb5_mk_priv(context, auth_context, &inbuf,
			       &msg_data, &replaydata))) {
        fprintf(stderr, "Error during Second Message Encoding: %s!\n",
		error_message(retval));
	free(inbuf.data);
        return(1);
    }
    free(inbuf.data);
    
    /* write private message to server */
    if (krb5_write_message(context, local_socket, &msg_data)){
        fprintf(stderr, "Write Error During Second Message Transmission!\n");
        return(1);
    } 
    
    free(msg_data.data);
    
     if (retval = krb5_read_message(context, local_socket, &inbuf)){
        fprintf(stderr, "Read Error During Second Reply: %s!\n",
		error_message(retval));
        return(1);
    }
    
    if (retval = krb5_rd_priv(context, auth_context, &inbuf,
			      &msg_data, &replaydata)) {
        fprintf(stderr, "Error during Second Read Decoding :%s!\n", 
		error_message(retval));
	free(inbuf.data);
        return(1);
    }
    free(inbuf.data);
    
    if (msg_data.data[2] == KADMBAD) {
	decode_kadmind_reply(msg_data, &rd_priv_resp);

	if (rd_priv_resp.message) {
	    fprintf(stderr, "%s\n\n", rd_priv_resp.message);
	    free(rd_priv_resp.message);
	} else
	    fprintf(stderr, "Generic error from server.\n\n");
	free(msg_data.data);
        return(0);
    }
    
#ifdef MACH_PASS
    pwsize = msg_data.length;
    if ((password = (char *) calloc (1, pwsize)) == (char *) 0) {
	fprintf(stderr, "No Memory for allocation of password!\n");
	retval = 1;
	free(msg_data.data);
	return(1);
    }
    
    memcpy(password, msg_data.data, pwsize);
    memset(msg_data.data, 0, pwsize);
    password[pwsize] = '\0';
    fprintf(stdout, "\nPassword for \"%s\" is \"%s\"\n", username, password);
    memset(password, 0, pwsize);
    free(password);
    fprintf(stdout, "\nThis password can only be used to execute kpasswd\n\n");
    
    free(msg_data.data);
    
    if ((inbuf.data = (char *) calloc(1, 2)) == (char *) 0) {
        fprintf(stderr, "No memory for command!\n");
        return(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = KADMGOOD;
    inbuf.length = 2;
   
#else

    free(msg_data.data);

    if ((password = (char *) calloc (1, ADM_MAX_PW_LENGTH+1)) == (char *) 0) {
	fprintf(stderr, "No Memory for allocation of password!\n");
	return(1);
    }

    pwsize = ADM_MAX_PW_LENGTH+1;
    
    putchar('\n');
    if (retval = krb5_read_password(context, 
				     DEFAULT_PWD_STRING1,
				     DEFAULT_PWD_STRING2,
				     password,
				     &pwsize)) {
	fprintf(stderr, "Error while reading new password for %s: %s!\n",
		username, error_message(retval));
	(void) memset((char *) password, 0, ADM_MAX_PW_LENGTH+1);
	free(password);
	return(1);
    }
    
    if ((inbuf.data = (char *) calloc(1, strlen(password) + 1)) == (char *) 0) {
	fprintf(stderr, "No Memory for allocation of buffer!\n");
	(void) memset((char *) password, 0, ADM_MAX_PW_LENGTH+1);
	free(password);
        return(1);
    }
     
    inbuf.length = strlen(password);
    (void) memcpy(inbuf.data, password, strlen(password));
    free(password);

#endif /* MACH_PASS */

    if ((retval = krb5_mk_priv(context, auth_context, &inbuf,
			       &msg_data, &replaydata))) {
        fprintf(stderr, "Error during Second Message Encoding: %s!\n",
		error_message(retval));
	free(inbuf.data);
        return(1);
    }
    free(inbuf.data);
    
    /* write private message to server */
    if (krb5_write_message(context, local_socket, &msg_data)){
        fprintf(stderr, "Write Error During Second Message Transmission!\n");
        return(1);
    } 
    free(msg_data.data);
    
    /* Ok Now let's get the final private message */
    if (retval = krb5_read_message(context, local_socket, &inbuf)){
        fprintf(stderr, "Read Error During Final Reply: %s!\n",
		error_message(retval));
        retval = 1;
    }
    
    if ((retval = krb5_rd_priv(context, auth_context, &inbuf,
			       &msg_data, &replaydata))) {
        fprintf(stderr, "Error during Final Read Decoding :%s!\n",
		error_message(retval));
	free(inbuf.data);
        return(1);
    }
    free(inbuf.data);
    
    decode_kadmind_reply(msg_data, &rd_priv_resp);

    free(msg_data.data);

    retval = print_status_message(&rd_priv_resp,
				  "Database Addition Successful.");
    
    return(retval);
}
