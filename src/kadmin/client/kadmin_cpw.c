/*
 * kadmin/client/kadmin_cpw.c
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
 * kadmin_cpw
 * Perform Remote Kerberos Administrative Functions
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <com_err.h>

#include <sys/param.h>

#include <k5-int.h>
#include "adm_defs.h"

void decode_kadmind_reply();
int print_status_message();

krb5_error_code
kadm_cpw_user(context, auth_context, my_creds, 
	      local_socket, oper_type, principal)
    krb5_context context;
    krb5_auth_context *auth_context;
    int *local_socket;
    int oper_type;
    char *principal;
{
    krb5_data msg_data, inbuf;
    kadmin_requests rd_priv_resp;
    char username[255];
    char *password;
    int pwsize;
    int count;
    krb5_replay_data replaydata;
    krb5_error_code retval;     /* return code */

    if ((inbuf.data = (char *) calloc(1, 3 + sizeof(username))) == (char *) 0) {        fprintf(stderr, "No memory for command!\n");
        exit(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = oper_type;
    inbuf.data[2] = SENDDATA2;

    if (principal && principal[0] != '\0')
      strcpy(username, principal);
    else {
	count = 0;
	do {
	    fprintf(stdout, 
		    "\nName of Principal Whose Password is to Change: ");
	    fgets(username, sizeof(username), stdin);
	    if (username[0] == '\n')
		fprintf(stderr, "Invalid Principal name!\n");
	    count++;
	}
	while (username[0] == '\n' && count < 3);

	if (username[0] == '\n') {
	    fprintf(stderr, "Aborting!!\n\n");
	    return(1);
	}

	username[strlen(username) -1] = '\0';
    }
    
    (void) memcpy( inbuf.data + 3, username, strlen(username));
    inbuf.length = strlen(username) + 3;

	/* Transmit Principal Name */
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
	free(msg_data.data);
        fprintf(stderr, "Write Error During Second Message Transmission!\n");
        return(1);
    } 
    free(msg_data.data);

    if (retval = krb5_read_message(context, local_socket, &inbuf)){
        fprintf(stderr, "Read Error During Second Reply: %s!\n",
			error_message(retval));
        return(1);
    }

    if ((retval = krb5_rd_priv(context, auth_context, &inbuf,
			       &msg_data, &replaydata))) {
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
	memset(msg_data.data, 0, msg_data.length);
	free(msg_data.data);
        return(0);
    }

    if ((oper_type == CHGOPER && msg_data.data[3] == KRB5_KDB_SALTTYPE_V4) ||
	(oper_type == CH4OPER && msg_data.data[3] == KRB5_KDB_SALTTYPE_NORMAL))
      fprintf(stderr, "WARNING: Changing Principal Salt type to %s!\n",
	      (msg_data.data[3] == KRB5_KDB_SALTTYPE_V4) ? 
	      "Version 5 Normal" : "Version 4");

#ifdef MACH_PASS /* Machine-generated passwords */
    pwsize = msg_data.length;
    if ((password = (char *) calloc (1, pwsize)) == (char *) 0) {
        fprintf(stderr, "No Memory for allocation of password!\n");
	memset(msg_data.data, 0, msg_data.length);
	free(msg_data.data);
        return(1);
    }

    memcpy(password, msg_data.data, pwsize);
    memset(msg_data.data, 0, pwsize);
    free(msg_data.data);
    password[pwsize] = '\0';
    fprintf(stdout, "\nPassword for \"%s\" is \"%s\"\n", username, password);
    memset(password, 0, pwsize);
    free(password);
    fprintf(stdout, "\nThis password can only be used to execute kpasswd\n\n");
 
    if ((inbuf.data = (char *) calloc(1, 2)) == (char *) 0) {
        fprintf(stderr, "No memory for command!\n");
        return(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = KADMGOOD;
    inbuf.length = 2;

#else

    if ((password = (char *) calloc (1, ADM_MAX_PW_LENGTH+1)) == (char *) 0) {
	fprintf(stderr, "No Memory for allocation of password!\n");
	return(1);
    }
    
    pwsize = ADM_MAX_PW_LENGTH+1;
    
    putchar('\n');
    if ((retval = krb5_read_password(context, 
				     DEFAULT_PWD_STRING1,
				     DEFAULT_PWD_STRING2,
				     password,
				     &pwsize))) {
	fprintf(stderr, "Error while reading new password for %s: %s!\n",
		username, error_message(retval));
	(void) memset((char *) password, 0, ADM_MAX_PW_LENGTH+1);
	free(password);
	return(1);
    }
    
    if ((inbuf.data = (char *) calloc (1, strlen(password) + 1)) == 
	(char *) 0) {
	fprintf(stderr, "No Memory for allocation of buffer!\n");
	(void) memset((char *) password, 0, ADM_MAX_PW_LENGTH+1);
	free(password);
	return(1);		/* No Memory */
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

    decode_kadmind_reply(msg_data, &rd_priv_resp);

    free(inbuf.data);
    free(msg_data.data);

    print_status_message(&rd_priv_resp,
			 "Password Modification Successful.");
    
    return(0);
}
