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
static char rcsid_adm_process[] =
"$Header$";
#endif	/* lint */

/*
  adm_process.c
*/

#include <sys/types.h>
#include <syslog.h>
#include <sys/wait.h>
#include <stdio.h>
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

extern krb5_encrypt_block master_encblock;
extern krb5_keyblock master_keyblock;

struct cpw_keyproc_arg {
    krb5_keyblock *key;
};

static krb5_error_code
cpw_keyproc(DECLARG(krb5_pointer, keyprocarg),
		DECLARG(krb5_principal, server),
		DECLARG(krb5_kvno, key_vno),
		DECLARG(krb5_keyblock **, key))
OLDDECLARG(krb5_pointer, keyprocarg)
OLDDECLARG(krb5_principal, server)
OLDDECLARG(krb5_kvno, key_vno)
OLDDECLARG(krb5_keyblock **, key)
{
    krb5_error_code retval;
    krb5_db_entry cpw_entry;
    krb5_principal cpw_krb;
    krb5_keyblock *realkey;

    struct cpw_keyproc_arg *arg;

    krb5_boolean more;

    int nprincs = 1;

    arg = ( struct cpw_keyproc_arg *) keyprocarg;

    if (arg->key) {
	*key = arg->key;
    } else {
	if (retval = krb5_parse_name(client_server_info.name_of_service, 
				     &cpw_krb)) {
            syslog(LOG_ERR, 
		   "cpw_keyproc %d while attempting to parse \"%s\"",
		   client_server_info.name_of_service, retval);
            return(0);
	}

	if (retval = krb5_db_get_principal(cpw_krb, &cpw_entry, 
			&nprincs, &more)) {
            syslog(LOG_ERR, 
		   "cpw_keyproc %d while extracting %s entry",
		   client_server_info.name_of_service, retval);
            return(0);
	}

	if (!nprincs) return(0);

	if ((realkey = (krb5_keyblock *) calloc (1, 
		sizeof(krb5_keyblock))) == (krb5_keyblock * ) 0) {
	    krb5_db_free_principal(&cpw_entry, nprincs);
	    syslog(LOG_ERR, "cpw_keyproc: No Memory for server key");
	    close(client_server_info.client_socket);
	    return(0);
	}

	/* Extract the real kadmin/<realm> keyblock */
	if (retval = krb5_kdb_decrypt_key(
				&master_encblock,
				&cpw_entry.key,
				realkey)) {
	    krb5_db_free_principal(&cpw_entry, nprincs);
	    free(realkey);
	    syslog(LOG_ERR, 
		   "cpw_keyproc: Cannot extract %s from master key",
		   client_server_info.name_of_service);
	    exit(0);
	}

	*key = realkey;
    }

    return(0);
}

krb5_error_code
process_client(prog)
char *prog;
{
    krb5_error_code retval;

    struct cpw_keyproc_arg cpw_key;

    int on = 1;
    krb5_db_entry server_entry;

    krb5_ticket *client_creds;
    krb5_authenticator *client_auth_data;
    char retbuf[512];

    krb5_data final_msg;
    char completion_msg[520];
    kadmin_requests request_type;

    int number_of_entries;
    krb5_boolean more;
    int namelen;

    char *req_type = "";
    int otype;

    u_short data_len;
    krb5_data outbuf;
    krb5_data inbuf, msg_data;
    extern int errno;
    
    krb5_timestamp adm_time;

    outbuf.data = retbuf;
    if (setsockopt(client_server_info.client_socket, 
			SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
	syslog(LOG_ERR, "adm_process: setsockopt keepalive: %d", errno);
    }

		/* V4 kpasswd Protocol Hack */
		/* Read Length of Data */
    retval = krb5_net_read(client_server_info.client_socket,
		(char *) &data_len, 2);
    if (retval < 0) {
	syslog(LOG_ERR, "kadmind error: net_read Length Failure");
	(void) sprintf(retbuf, "kadmind error during net_read for Length\n");
	exit(0);
    }

    if (retval = krb5_db_init()) {		/* Open as client */
	syslog(LOG_ERR, "adm_process: Can't Open Database");
	close(client_server_info.client_socket);
	exit(0);
    }

/*	Get Server Credentials for Mutual Authentication and Private
 *	Messages  Note: Here client is the kadmin/<realm> server
 */
    number_of_entries = 1;
    if ((retval = krb5_db_get_principal(client_server_info.server,
			&server_entry,
			&number_of_entries,
			&more))) {
	syslog(LOG_ERR, 
		"kadmind error: krb5_db_get_principal error: %d", retval);
	close(client_server_info.client_socket);
	exit(0);
    }

    if (more) {
	krb5_db_free_principal(&server_entry, number_of_entries);
	syslog(LOG_ERR, "kadmind error: kadmin/<realm> service not unique");
	exit(1);
    }

    if (number_of_entries != 1) {
	krb5_db_free_principal(&server_entry, number_of_entries);
	syslog(LOG_ERR, "kadmind error: kadmin/<realm> service UNKNOWN");
	close(client_server_info.client_socket);
	exit(0);
    }

    if ((cpw_key.key = (krb5_keyblock *) calloc (1, 
		sizeof(krb5_keyblock))) == (krb5_keyblock *) 0) {
	krb5_db_free_principal(&server_entry, number_of_entries);
	syslog(LOG_ERR, 
	       "kadmind error: No Memory for server key");
	close(client_server_info.client_socket);
	exit(0);
    }

    /* Extract the real kadmin/<realm> keyblock */
    if (retval = krb5_kdb_decrypt_key(
				      &master_encblock,
				      &server_entry.key,
				      (krb5_keyblock *) cpw_key.key)) {
	krb5_db_free_principal(&server_entry, number_of_entries);
	free(cpw_key.key);
	syslog(LOG_ERR,  
	       "kadmind error: Cannot extract kadmin/<realm> from master key");
	close(client_server_info.client_socket);
	exit(0);
    }

/*
 *	To verify authenticity, we need to know the address of the
 *	client.
 */

    namelen = sizeof(client_server_info.client_addr);
    if (getpeername(client_server_info.client_socket, 
			(struct sockaddr *) &client_server_info.client_addr, 
			&namelen) < 0) {
	syslog(LOG_ERR,  "kadmind error: Unable to Obtain Client Name.");
	close(client_server_info.client_socket);
	exit(0);
    }

			/* we use mutual authentication */
    client_server_info.client_addr.addrtype = 
		client_server_info.client_name.sin_family;
    client_server_info.client_addr.length = SIZEOF_INADDR;
    client_server_info.client_addr.contents = 
		(krb5_octet *) &client_server_info.client_name.sin_addr;

    client_server_info.server_addr.addrtype = 
		client_server_info.server_name.sin_family;
    client_server_info.server_addr.length = SIZEOF_INADDR;
    client_server_info.server_addr.contents = 
		(krb5_octet *) &client_server_info.server_name.sin_addr;

    krb5_init_ets();

    syslog(LOG_AUTH | LOG_INFO,
	"Request for Administrative Service Received from %s - Authenticating.",
	inet_ntoa( client_server_info.client_name.sin_addr ));
	
    if ((retval = krb5_recvauth(
		(krb5_pointer) &client_server_info.client_socket,
		ADM5_CPW_VERSION,
		client_server_info.server,
		&client_server_info.client_addr,
		0,
		cpw_keyproc,
		(krb5_pointer) &cpw_key,
		0,
		&send_seqno,
		&client_server_info.client,
		&client_creds,
		&client_auth_data
		))) {
	syslog(LOG_ERR, "kadmind error: %s during recvauth\n", 
			error_message(retval));
	(void) sprintf(retbuf, "kadmind error during recvauth: %s\n", 
			error_message(retval));
    } else {
	/* Check if ticket was issued using password (and not tgt)
	   within the last 5 minutes */
	
	if (!(client_creds->enc_part2->flags & TKT_FLG_INITIAL)) {
	    syslog(LOG_ERR,
		 "Client ticket not initial");
	    close(client_server_info.client_socket);
	    exit(0);
	}

	if (retval = krb5_timeofday(&adm_time)) {
	    syslog(LOG_ERR,
		 "Can't get time of day");
	    close(client_server_info.client_socket);
	    exit(0);
	}
	
	if ((client_creds->enc_part2->times.authtime - adm_time) > 60*5) {
	    syslog(LOG_ERR,
		 "Client ticket not recent");
	    close(client_server_info.client_socket);
	    exit(0);
	}

	recv_seqno = client_auth_data->seq_number;

	if ((client_server_info.name_of_client =
			(char *) calloc (1, 3 * 255)) == (char *) 0) {
	    syslog(LOG_ERR, "kadmind error: No Memory for name_of_client");
	    close(client_server_info.client_socket);
	    exit(0);
	}

	if ((retval = krb5_unparse_name(client_server_info.client, 
			&client_server_info.name_of_client))) {
	     syslog(LOG_ERR, "kadmind error: unparse failed.", 
				error_message(retval));
	    goto finish;
	}

	syslog(LOG_AUTH | LOG_INFO,
		"Request for Administrative Service Received from %s at %s.",
		client_server_info.name_of_client,
		inet_ntoa( client_server_info.client_name.sin_addr ));
	
			/* compose the reply */
	outbuf.data[0] = KADMIND;
        outbuf.data[1] = KADMSAG;
        outbuf.length = 2;
    }

		/* write back the response */
    if ((retval = krb5_write_message(&client_server_info.client_socket,
					&outbuf))){
	syslog(LOG_ERR, "kadmind error: Write Message Failure: %s",
			error_message(retval));
	retval = 1;
	goto finish;
    }

	/* Ok Now let's get the first private message and respond */
    if (retval = krb5_read_message(&client_server_info.client_socket,
                                        &inbuf)){
	syslog(LOG_ERR, "kadmind error: read First Message Failure: %s",
		error_message(retval));
	retval = 1;
	goto finish;
    }

    if ((retval = krb5_rd_priv(&inbuf, 
			client_creds->enc_part2->session,
			&client_server_info.client_addr, 
			&client_server_info.server_addr,
			client_auth_data->seq_number,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data))) {
	syslog(LOG_ERR, "kadmind error: rd_priv:%s\n", error_message(retval));
	goto finish;
    }
    free(inbuf.data);

    request_type.appl_code = msg_data.data[0];
    request_type.oper_code = msg_data.data[1];

    free(msg_data.data);

    switch (request_type.appl_code) {
	case KPASSWD:
	    req_type = "kpasswd";
	    if (retval = adm5_kpasswd("process_client", &request_type, 
			client_creds, retbuf, &otype)) {
		goto finish;
	    }
	    break;

	case KADMIN:
	    req_type = "kadmin";
	    if (retval = adm5_kadmin("process_client", client_auth_data,
			client_creds, retbuf, &otype)) {
		goto finish;
	    }
	    retbuf[0] = KADMIN;
	    retbuf[2] = KADMGOOD;
	    retbuf[3] = '\0';
	    otype = 0;
	    break;

	default:
	    retbuf[0] = KUNKNOWNAPPL;
	    retbuf[1] = '\0';
	    sprintf(completion_msg, "%s from %s (%02x) FAILED", 
			"Unknown Application Type!", 
			inet_ntoa(client_server_info.client_name.sin_addr),
		    request_type.appl_code);
		/* Service Not Supported */
	    retval = 255;
	    syslog(LOG_AUTH | LOG_INFO, completion_msg);
	    goto finish;
    }				/* switch(request_type.appl_code) */

    if ((final_msg.data = (char *) calloc(1,10)) == (char *) 0) {
	syslog(LOG_ERR | LOG_INFO, "no Memory while allocating final_msg.data");
	return ENOMEM;
    }
    final_msg.data = retbuf;
    final_msg.length = strlen(retbuf) + 1;

                /* Send Completion Message */
    if (retval = krb5_mk_priv(&final_msg,
                        ETYPE_DES_CBC_CRC,
                        client_creds->enc_part2->session,
                        &client_server_info.server_addr,
                        &client_server_info.client_addr,
                        send_seqno,
                        KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
                        0,
                        0,
                        &msg_data)) {
	syslog(LOG_ERR, "kadmind error Error Performing Final mk_priv");
	free(final_msg.data);
	goto finish;
    }
    free(final_msg.data);
    
        /* Send Final Reply to Client */
    if (retval = krb5_write_message(&client_server_info.client_socket,
					&msg_data)){
	syslog(LOG_ERR, "Error Performing Final Write: %s",
			error_message(retval));
	retval = 1;
	goto finish;
    }
    free(msg_data.data);

finish:

    if (retval) {
	free (client_server_info.name_of_client);
	close(client_server_info.client_socket);
	exit(1);
    }
 
    sprintf(completion_msg,
        "%s %s for %s at %s - Completed Successfully",
	req_type,
	oper_type[otype],
        client_server_info.name_of_client, 
        inet_ntoa( client_server_info.client_name.sin_addr )); 
    syslog(LOG_AUTH | LOG_INFO, completion_msg);
    free (client_server_info.name_of_client);
    close(client_server_info.client_socket);
    return 0;
}
