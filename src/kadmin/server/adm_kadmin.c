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
static char rcsid_adm_kadmin[] =
"$Header$";
#endif  /* lint */

/*
  adm_kadmin.c
*/

#include <sys/types.h>
#include <syslog.h>
#include <com_err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif
 
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/kdb.h>
#include <krb5/adm_defs.h>
#include "adm_extern.h"
 
krb5_error_code
adm5_kadmin(prog, client_auth_data, client_creds, retbuf, otype)
char *prog;
krb5_authenticator *client_auth_data;
krb5_ticket *client_creds;
char *retbuf;		/* Allocated in Calling Routine */
int *otype;
{
    krb5_error_code retval;
    kadmin_requests request_type;
    krb5_data msg_data, outbuf, inbuf;

    char *customer_name;
    char *completion_msg;
    int length_of_name;

    int salttype;

    outbuf.data = retbuf;	/* Do NOT free outbuf.data */

    for ( ; ; ) {		/* Use "return", "break", or "goto" 
				   to exit for loop */

		/* Encode Acknowledgement Message */
	retbuf[0] = KADMIND;
	retbuf[1] = KADMSAG;
	retbuf[2] = SENDDATA2;
	outbuf.length = 3;

	retval = krb5_mk_priv(&outbuf,
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
	    syslog(LOG_ERR, 
		"adm5_kadmin - Error Performing Acknowledgement mk_priv");
	    return(5);		/* Protocol Failure */
	}

		/* Send Acknowledgement Reply to Client */
	if (retval = krb5_write_message(&client_server_info.client_socket,
				&msg_data)){
	    syslog(LOG_ERR,
		"adm5_kadmin - Error Performing Acknowledgement Write: %s",
		error_message(retval));
	    return(5);		/* Protocol Failure */
	}
	free(msg_data.data);

			/* Read Username */
	if (krb5_read_message(&client_server_info.client_socket, &inbuf)){
	    syslog(LOG_ERR | LOG_INFO, "Error Performing Username Read");
	    return(5);		/* Protocol Failure */
	}

                /* Decrypt Client Response */
	if ((retval = krb5_rd_priv(&inbuf,
			client_creds->enc_part2->session,
			&client_server_info.client_addr,
			&client_server_info.server_addr,
			recv_seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data))) {
	    free(inbuf.data);
	    syslog(LOG_ERR | LOG_INFO, "Error decoding Username - rd_priv");
	    return(5);		/* Protocol Failure */
	}
	free(inbuf.data);

	request_type.appl_code = msg_data.data[0];
	request_type.oper_code = msg_data.data[1];
	if (msg_data.data[2] != SENDDATA2) {
	    syslog(LOG_ERR | LOG_INFO, 
		"Invalid Protocol String - Response not SENDDATA2");
	    free(msg_data.data);
	    return(5);		/* Protocol Failure */
	}

	length_of_name = msg_data.length - 3;

	if (request_type.oper_code == COMPLETE) {
	    *otype = 0;
	    free(msg_data.data);
	    retval = 0;
	    goto finish_req;
	}

	if (!length_of_name) {
	    syslog(LOG_ERR,
		"adm5_kadmin error: Invalid KADMIN request - No Customer");
	    free(msg_data.data);
	    return(5);		/* Protocol Error */
	}

	if ((customer_name = (char *) calloc(1, length_of_name + 1)) == 
				(char *) 0) {
	    syslog(LOG_ERR, "adm5_kadmin error: No Memory for Customer Name");
	    free(msg_data.data);
	    return(3);		/* No Memory */
	}

	(void) memcpy(customer_name, (char *) msg_data.data + 3, 
			length_of_name);
	customer_name[length_of_name] = '\0';

	free(msg_data.data);

	if ((completion_msg = (char *) calloc (1,512)) == (char *) 0) {
	    syslog(LOG_ERR, "adm5_kadmin - No Memory for completion_msg");
	    free(customer_name);
	    return(3);		/* No Memory */
	}

	switch(request_type.oper_code) {
	    case ADDOPER:
			/* Check for Add Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "a")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 1;
		salttype = KRB5_KDB_SALTTYPE_NORMAL;
		retval = adm_add_new_key("adm5_kadmin", customer_name,
					 client_creds, salttype);
		goto process_retval;

	    case CHGOPER:
			/* Check for Password Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "c")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 2;
		salttype = KRB5_KDB_SALTTYPE_NORMAL;
		retval = adm_change_pwd("adm5_kadmin", customer_name,
					client_creds, salttype);
		goto process_retval;

	    case ADROPER:
			/* Check for Add Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "a")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 3;
		retval = adm_add_new_key_rnd("adm5_kadmin", customer_name,
					     client_creds);
		goto process_retval;

	    case CHROPER:
			/* Check for Password Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "c")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 4;
		retval = adm_change_pwd_rnd("adm5_kadmin", customer_name,
					    client_creds);
		goto process_retval;

	    case DELOPER:
			/* Check for Delete Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "d")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 5;
		retval = adm_del_old_key("adm5_kadmin", customer_name);
		goto process_retval;

	    case MODOPER:
		/* Check for Modify Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "m")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 6;
		retval = adm_mod_old_key("adm5_kadmin", customer_name,
					 client_creds);
		goto process_retval;

	    case INQOPER:
			/* Check for Inquiry Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "i")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 7;
		retval = adm_inq_old_key("adm5_kadmin", customer_name,
					 client_creds);
		goto process_retval;

	    case AD4OPER:
			/* Check for Add Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "a")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 8;
		salttype = KRB5_KDB_SALTTYPE_V4;
		retval = adm_add_new_key("adm5_kadmin", customer_name,
					 client_creds, salttype);
		goto process_retval;

	    case CH4OPER:
			/* Check for Password Privilege */
		if (retval = adm_check_acl(client_server_info.name_of_client,
					   "c")) {
		    retval = 7;
		    goto process_retval;
		}
		*otype = 9;
		salttype = KRB5_KDB_SALTTYPE_V4;
		retval = adm_change_pwd("adm5_kadmin", customer_name,
					client_creds, salttype);
		goto process_retval;

	    default:
		retbuf[0] = KADMIN;
		retbuf[1] = KUNKNOWNOPER;
		retbuf[2] = '\0';
		sprintf(completion_msg, "%s %s from %s FAILED",
			"kadmin", 
			"Unknown or Non-Implemented Operation Type!",
			inet_ntoa(client_server_info.client_name.sin_addr));
	        syslog(LOG_AUTH | LOG_INFO, completion_msg);
		free(completion_msg);
		retval = 255;
		goto send_last;
	}			/* switch (request_type.oper_code) */

process_retval:
	switch (retval) {
	    case 0:
		retbuf[0] = KADMIN;
		retbuf[1] = request_type.oper_code;
		retbuf[2] = KADMGOOD;
		retbuf[3] = '\0';
		goto send_last;

	    case 1:     /* Principal Unknown */
	    case 2:     /* Principal Already Exists */
	    case 3:     /* ENOMEM */
	    case 4:     /* Password Failure */
	    case 5:     /* Protocol Failure */
	    case 6:     /* Security Failure */
	    case 7:     /* Admin Client Not in ACL List */
	    case 8:     /* Database Update Failure */
		retbuf[0] = KADMIN;
		retbuf[1] = request_type.oper_code;
		retbuf[2] = KADMBAD;
		retbuf[3] = '\0';
		sprintf((char *)retbuf +3, "%s",
			kadmind_kadmin_response[retval]);
		sprintf(completion_msg, 
			"%s %s from %s FAILED - %s", 
			"kadmin",
			oper_type[request_type.oper_code],
			inet_ntoa(client_server_info.client_name.sin_addr),
			kadmind_kadmin_response[retval]);
		syslog(LOG_AUTH | LOG_INFO, completion_msg);
		free(completion_msg);
		goto send_last;

	    default:
		retbuf[0] = KADMIN;
		retbuf[1] = request_type.oper_code;
		retbuf[2] = KUNKNOWNERR;
		retbuf[3] = '\0';
		sprintf(completion_msg, "%s %s from %s FAILED", 
		    "ksrvutil",
		    oper_type[1],
		    inet_ntoa( client_server_info.client_name.sin_addr));
		syslog(LOG_AUTH | LOG_INFO, completion_msg);
		retval = 255;
		goto send_last;
	}		/* switch(retval) */

send_last:
	free(customer_name);
	free(completion_msg);
	outbuf.data = retbuf;
	outbuf.length = strlen(retbuf) + 1;

		/* Send Completion Message */
	if (retval = krb5_mk_priv(&outbuf,
			ETYPE_DES_CBC_CRC,
			client_creds->enc_part2->session,
			&client_server_info.server_addr,
			&client_server_info.client_addr,
			send_seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data)) {
	    syslog(LOG_ERR, "adm5_kadmin - Error Performing Final mk_priv");
	    return(1);
	}

			/* Send Final Reply to Client */
	if (retval = krb5_write_message(&client_server_info.client_socket,
					&msg_data)){
	    syslog(LOG_ERR, "adm5_kadmin - Error Performing Final Write: %s",
			error_message(retval));
	    return(1);
	}
	free(msg_data.data);
    }		/* for */

finish_req:
    return(retval);
}
