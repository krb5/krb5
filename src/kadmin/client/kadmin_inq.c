/*
 * $Source$
 * $Author$
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

#if !defined(lint) && !defined(SABER)
static char rcsid_kadmin_inq[] =
    "$Header$";
#endif	/* lint */

/*
 * kadmin_inq
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

#include <krb5/adm_defs.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>

void decode_kadmind_reply();
int print_status_message();

krb5_error_code
kadm_inq_user(my_creds, rep_ret, local_addr, foreign_addr, 
	      local_socket, seqno, principal)
krb5_creds *my_creds;
krb5_ap_rep_enc_part *rep_ret;
krb5_address *local_addr, *foreign_addr;
int *local_socket;
krb5_int32 *seqno;
char *principal;
{
    krb5_data msg_data, inbuf;
    kadmin_requests rd_priv_resp;
    char username[755];
    int count;
    krb5_error_code retval;     /* return code */
    char *my_data;

    if ((inbuf.data = (char *) calloc(1, 3 + sizeof(username))) == (char *) 0) {
        fprintf(stderr, "No memory for command!\n");
        return(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = INQOPER;
    inbuf.data[2] = SENDDATA2;
    
    if (principal && principal[0] != '\0')
	strcpy(username, principal);
    else {
	count = 0;
	do {
	    fprintf(stdout, "\nName of Principal to be Displayed: ");
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
 
    if (retval = krb5_mk_priv(&inbuf,
			ETYPE_DES_CBC_CRC,
			&my_creds->keyblock, 
			local_addr, 
			foreign_addr,
			*seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data)) {
        fprintf(stderr, "Error during Second Message Encoding: %s!\n",
			error_message(retval));
	free(inbuf.data);
	return(1);
    }
    free(inbuf.data);

    /* write private message to server */
    if (krb5_write_message(local_socket, &msg_data)){
        fprintf(stderr, "Write Error During Second Message Transmission!\n");
        return(1);
    } 
    free(msg_data.data);

    /* Ok Now let's get the private message */
    if ((retval = krb5_read_message(local_socket, &inbuf))){
        fprintf(stderr, "Read Error During Second Reply: %s!\n",
			error_message(retval));
        return(1);
    }

    if (retval = krb5_rd_priv(&inbuf,
			&my_creds->keyblock,
    			foreign_addr, 
			local_addr,
			rep_ret->seq_number, 
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data)) {
        fprintf(stderr, "Error during Second Read Decoding :%s!\n", 
			error_message(retval));
	free(inbuf.data);
        return(1);
    }
    free(inbuf.data);

    if (!msg_data.data) {
        fprintf(stderr, "kadm_inq_user: Error - empty message received!\n\n");
        return(0);
    }
	
    if (msg_data.data[2] == KADMBAD) {
	decode_kadmind_reply(msg_data, &rd_priv_resp);

	if (rd_priv_resp.message) {
	    fprintf(stderr, "%s\n\n", rd_priv_resp.message);
	    free(rd_priv_resp.message);
	} else
	    fprintf(stderr, "Generic error from server.\n\n");
        return(0);
    }

    my_data = malloc(msg_data.length + 1);
    if (!my_data) {
	fprintf(stderr, "kadmin_inq: Couldn't allocate space for my_data!\n");
	exit(1);
    }
    memcpy(my_data, msg_data.data, msg_data.length);
    my_data[msg_data.length] = 0;

		/* Print Inquiry Information */
    fprintf(stdout, "%s\n", my_data);
    free(my_data);
    free(msg_data.data);

    if ((inbuf.data = (char *) calloc(1, 3)) == (char *) 0) {
	fprintf(stderr, "inbuf.data allocation error!\n");
	return(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = KADMGOOD;
    inbuf.length = 2;
 
    if (retval = krb5_mk_priv(&inbuf,
                        ETYPE_DES_CBC_CRC,
                        &my_creds->keyblock,
                        local_addr,
                        foreign_addr,
                        *seqno,
                        KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
                        0,
                        0,
                        &msg_data)) {
        fprintf(stderr, "Error during Second Message Encoding: %s!\n",
                        error_message(retval));
	free(inbuf.data);
        return(1);
    }
    free(inbuf.data);
     
         /* write private message to server */
    if (krb5_write_message(local_socket, &msg_data)){
        fprintf(stderr, "Write Error During Second Message Transmission!\n");
        free(msg_data.data);
        return(1);
    }
    free(msg_data.data);

                /* Ok Now let's get the final private message */
    if (retval = krb5_read_message(local_socket, &inbuf)){
        fprintf(stderr, "Read Error During Final Reply: %s!\n",
                        error_message(retval));
        retval = 1;
    }
 
    if (retval = krb5_rd_priv(&inbuf,
                        &my_creds->keyblock,
                        foreign_addr,
                        local_addr,
                        rep_ret->seq_number,
                        KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
                        0,
                        0,
                        &msg_data)) {
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
			 "Password Inquiry Successful.");
    
    return(0);
}
