/*
 * kadmin/client/kadmin_cpr.c
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
 * kadmin_cpr
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

#include <krb5.h>
#include "adm_defs.h"

void decode_kadmind_reply();
int print_status_message();

krb5_error_code
kadm_cpw_user_rnd(context, auth_context, my_creds, 
		  local_socket, seqno, principal)
    krb5_context context;
    krb5_auth_context *auth_context;
    int *local_socket;
    krb5_int32 *seqno;
    char *principal;
{
    krb5_data msg_data, inbuf;
    kadmin_requests rd_priv_resp;
    char username[755];
    int count;
    krb5_replay_data replaydata;
    krb5_error_code retval;     /* return code */

    if ((inbuf.data = (char *) calloc(1, 3 + sizeof(username))) == (char *) 0) {        fprintf(stderr, "No memory for command!\n");
        exit(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = CHROPER;
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

    free(inbuf.data);
    free(msg_data.data);

    print_status_message(&rd_priv_resp,
			 "Password Modification Successful.");
    
    return(0);
}


