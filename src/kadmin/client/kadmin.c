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
static char rcsid_kadmin[] =
    "$Header$";
#endif	/* lint */

/*
 * kadmin
 * Perform Remote Kerberos Administrative Functions
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include <com_err.h>

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

#include <krb5/adm_defs.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>

/*
 * Try no preauthentication first; then try the encrypted timestamp
 */
int preauth_search_list[] = {
	0,			
	KRB5_PADATA_ENC_TIMESTAMP,
	-1
	};

krb5_error_code get_first_ticket 
	PROTOTYPE((krb5_ccache, 
		krb5_principal));

struct sockaddr_in local_sin, remote_sin;

krb5_creds my_creds;

void get_def_princ();
void decode_kadmind_reply();
int print_status_message();

main(argc,argv)
  int argc;
  char *argv[];
{
    extern char *optarg;

    krb5_ccache cache = NULL;
    char cache_name[255];

    krb5_address local_addr, foreign_addr;

    krb5_principal client;

    char *client_name;	/* Single string representation of client id */

    krb5_data *requested_realm;

    krb5_error_code retval;	/* return code */

    int local_socket;

    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;

    kadmin_requests rd_priv_resp;

    krb5_checksum send_cksum;
    krb5_data msg_data, inbuf;
    krb5_int32 seqno;
    char buffer[255];
    char command_type[120];
    char princ_name[120];
    int i, valid;
    int option;
    int oper_type;

    krb5_init_ets();
    client_name = (char *) malloc(755);
    memset((char *) client_name, 0, sizeof(client_name));

    if (argc > 3)
      usage();

    if (argc == 1) {  /* No User Specified */
	get_def_princ(&client);
	strcpy(client_name, client->data[0].data);
	strncat(client_name, "/admin@", 7);
	strncat(client_name, client->realm.data, client->realm.length);
	if (retval = krb5_parse_name(client_name, &client)) {
	    fprintf(stderr, "Unable to Parse Client Name!\n");
	    usage();
	}
    }
    else {
	while ((option = getopt(argc, argv, "n")) != EOF) {
	    switch (option) {
	      case 'n':
		if (argc == 3) {
		    strcpy(client_name, argv[2]);
		    if (retval = krb5_parse_name(client_name, &client)) {
			fprintf(stderr, "Unable to Parse Client Name!\n");
			usage();
		    }
		}
		else {
		    get_def_princ(&client);
		    if (retval = krb5_unparse_name(client, &client_name)) {
			fprintf(stderr, "Unable to unparse Client Name!\n");
			usage();
		    }
		}
		break;
	      case '?':
	      default:
		usage();
		break;
	    }
	}
	
	if (client_name[0] == '\0') { /* No -n option specified */
	    if (argc > 2)
	      usage();
	    strcpy(client_name, argv[1]);
	    if (!strncmp("help", client_name, strlen(client_name))) 
	      usage();
	    if (!strncmp("root", client_name, strlen(client_name))) {
    		fprintf(stderr, "root is not a valid Administrator!\n\n");
		usage();
	    }
	    if (retval = krb5_parse_name(client_name, &client)) {
		fprintf(stderr, "Error Parsing User Specified Name Option!\n");
		exit(1);
	    }
	} 
    }	/* switch */

	/* Create credential cache for kadmin */
    (void) sprintf(cache_name, "FILE:/tmp/tkt_adm_%d", getpid());

    if ((retval = krb5_cc_resolve(cache_name, &cache))) {
	fprintf(stderr, "Unable to Resolve Cache: !\n", cache_name);
    }
    
    if ((retval = krb5_cc_initialize(cache, client))) {
        fprintf(stderr, "Error initializing cache: %s!\n", cache_name);
        exit(1);
    }
 
/*
 *	Verify User by Obtaining Initial Credentials prior to Initial Link
 */

    if ((retval = get_first_ticket(cache, client))) {
        (void) krb5_cc_destroy(cache);
	exit(1);
    }
    /* my_creds has the necessary credentials for further processing:
       Destroy credential cache for security reasons */
    (void) krb5_cc_destroy(cache);
    
    requested_realm = (krb5_data *) &client->realm;


	/* Initiate Link to Server */
    if ((retval = adm5_init_link(requested_realm, &local_socket))) {
	(void) krb5_cc_destroy(cache);
	exit(1);
    } 

#ifdef unicos61
#define SIZEOF_INADDR  SIZEOF_in_addr
#else
#define SIZEOF_INADDR sizeof(struct in_addr)
#endif

/* V4 kpasswd Protocol Hack
 *	Necessary for ALL kadmind clients
 */
    {
	int msg_length = 0;

	retval = krb5_net_write(local_socket, (char *) &msg_length + 2, 2);
	if (retval < 0) {
	    fprintf(stderr, "krb5_net_write failure!\n");
            (void) krb5_cc_destroy(cache);
	    exit(1);
	}
    }

    local_addr.addrtype = ADDRTYPE_INET;
    local_addr.length = SIZEOF_INADDR ;
    local_addr.contents = (krb5_octet *) &local_sin.sin_addr;

    foreign_addr.addrtype = ADDRTYPE_INET;
    foreign_addr.length = SIZEOF_INADDR ;
    foreign_addr.contents = (krb5_octet *) &remote_sin.sin_addr;

		/* compute checksum, using CRC-32 */
    if (!(send_cksum.contents = (krb5_octet *)
	malloc(krb5_checksum_size(CKSUMTYPE_CRC32)))) {
        fprintf(stderr, "Insufficient Memory while Allocating Checksum!\n");
        (void) krb5_cc_destroy(cache);
        exit(1);
    }

		/* choose some random stuff to compute checksum from */
	if (retval = krb5_calculate_checksum(CKSUMTYPE_CRC32,
					ADM5_ADM_VERSION,
					strlen(ADM5_ADM_VERSION),
					0,
					0, /* if length is 0, crc-32 doesn't
                                               use the seed */
					&send_cksum)) {
        fprintf(stderr, "Error while Computing Checksum: %s!\n",
		error_message(retval));
	free(send_cksum.contents);
        (void) krb5_cc_destroy(cache);
        exit(1);
    }

    /* call Kerberos library routine to obtain an authenticator,
       pass it over the socket to the server, and obtain mutual
       authentication. */

    if ((retval = krb5_sendauth((krb5_pointer) &local_socket,
			ADM_CPW_VERSION, 
			my_creds.client, 
			my_creds.server,
			AP_OPTS_MUTUAL_REQUIRED,
			&send_cksum,
			&my_creds,           
			0,
			&seqno, 
			0,           /* don't need a subsession key */
			&err_ret,
			&rep_ret))) {
	fprintf(stderr, "Error while performing sendauth: %s!\n",
			error_message(retval));
	free(send_cksum.contents);
	exit(1);
    }

	/* Read back what the server has to say ... */
    if (retval = krb5_read_message(&local_socket, &inbuf)){
	fprintf(stderr, " Read Message Error: %s!\n",
			error_message(retval));
	free(send_cksum.contents);
        exit(1);
    }

    if ((inbuf.length != 2) || (inbuf.data[0] != KADMIND) ||
			(inbuf.data[1] != KADMSAG)){
	fprintf(stderr, " Invalid ack from admin server.!\n");
	free(send_cksum.contents);
        exit(1);
    }
    free(inbuf.data);

    if ((inbuf.data = (char *) calloc(1, 2)) == (char *) 0) {
	fprintf(stderr, "No memory for command!\n");
	free(send_cksum.contents);
        exit(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = 0xff;
    inbuf.length = 2;

    if ((retval = krb5_mk_priv(&inbuf,
			ETYPE_DES_CBC_CRC,
			&my_creds.keyblock, 
			&local_addr, 
			&foreign_addr,
			seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data))) {
	fprintf(stderr, "Error during First Message Encoding: %s!\n",
			error_message(retval));
	free(inbuf.data);
	free(send_cksum.contents);
        exit(1);
    }
    free(inbuf.data);

		/* write private message to server */
    if (krb5_write_message(&local_socket, &msg_data)){
	fprintf(stderr, "Write Error During First Message Transmission!\n");
	free(send_cksum.contents);
        exit(1);
    } 
    free(msg_data.data);

    for ( ; ; ) {
		/* Ok Now let's get the private message */
	if (retval = krb5_read_message(&local_socket, &inbuf)){
	    fprintf(stderr, "Read Error During First Reply: %s!\n",
			error_message(retval));
	    free(send_cksum.contents);
            exit(1);
	}

	if ((retval = krb5_rd_priv(&inbuf,
			&my_creds.keyblock,
    			&foreign_addr, 
			&local_addr,
			rep_ret->seq_number, 
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data))) {
	    fprintf(stderr, "Error during First Read Decoding: %s!\n", 
			error_message(retval));
	    free(send_cksum.contents);
            exit(1);
	}
	free(inbuf.data);

	valid = 0;
	princ_name[0] = '\0';
repeat:
	printf("\n\nCommand (add, cpw, del, inq, mod, addrnd, cpwrnd, addv4, cpwv4, q): ");
	fgets(buffer, sizeof(buffer), stdin);
	buffer[strlen(buffer) -1] = '\0';
	sscanf(buffer,"%s %s", command_type, princ_name);
	for (i = 0; command_type[i] != '\0'; i++)
	    if (isupper(command_type[i]))
		command_type[i] = tolower(command_type[i]);
	
	if (!strcmp(command_type, "add")) {
	    valid++;
	    oper_type = ADDOPER;
	    if (retval = kadm_add_user(&my_creds, 
				       rep_ret,
				       &local_addr, 
				       &foreign_addr, 
				       &local_socket, 
				       &seqno,
				       oper_type,
				       princ_name)) break;
	}
	if (!strcmp(command_type, "cpw")) {
	    valid++;
	    oper_type = CHGOPER;
	    if (retval = kadm_cpw_user(&my_creds, 
				       rep_ret,
				       &local_addr, 
				       &foreign_addr, 
				       &local_socket, 
				       &seqno,
				       oper_type,
				       princ_name)) break;
	}
	if (!strcmp(command_type, "addrnd")) {
	    valid++;
	    if (retval = kadm_add_user_rnd(&my_creds, 
					   rep_ret,
					   &local_addr, 
					   &foreign_addr, 
					   &local_socket, 
					   &seqno,
					   princ_name)) break;
	}
	if (!strcmp(command_type, "cpwrnd")) {
	    valid++;
	    if (retval = kadm_cpw_user_rnd(&my_creds, 
					   rep_ret,
					   &local_addr, 
					   &foreign_addr, 
					   &local_socket, 
					   &seqno,
					   princ_name)) break;
	}
	if (!strcmp(command_type, "del")) {
	    valid++;
	    if (retval = kadm_del_user(&my_creds, 
				       rep_ret,
				       &local_addr, 
				       &foreign_addr, 
				       &local_socket, 
				       &seqno,
				       princ_name)) break;
	}
	if (!strcmp(command_type, "inq")) {
	    valid++;
	    if (retval = kadm_inq_user(&my_creds, 
				       rep_ret,
				       &local_addr, 
				       &foreign_addr, 
				       &local_socket, 
				       &seqno,
				       princ_name)) break;
	}
	if (!strcmp(command_type, "mod")) {
	    valid++;
	    if (retval = kadm_mod_user(&my_creds, 
				       rep_ret,
				       &local_addr, 
				       &foreign_addr, 
				       &local_socket, 
				       &seqno,
				       princ_name)) break;
	}
	if (!strcmp(command_type, "addv4")) {
	    valid++;
	    oper_type = AD4OPER;
	    if (retval = kadm_add_user(&my_creds, 
				       rep_ret,
				       &local_addr, 
				       &foreign_addr, 
				       &local_socket, 
				       &seqno,
				       oper_type,
				       princ_name)) break;
	}
	if (!strcmp(command_type, "cpwv4")) {
	    valid++;
	    oper_type = CH4OPER;
	    if (retval = kadm_cpw_user(&my_creds, 
				       rep_ret,
				       &local_addr, 
				       &foreign_addr, 
				       &local_socket, 
				       &seqno,
				       oper_type,
				       princ_name)) break;
	}
	if (!strcmp(command_type, "q")) { 
	    valid++;
	    retval = kadm_done(&my_creds, 
			       rep_ret,
			       &local_addr, 
			       &foreign_addr, 
			       &local_socket, 
			       &seqno);
	    break;
	}
	
	if (!valid) {
	    fprintf(stderr, "Invalid Input - Retry\n");
	    goto repeat;
	}
    }

    if (retval) {
	free(send_cksum.contents);
        exit(1);
    }

    		/* Ok Now let's get the final private message */
    if (retval = krb5_read_message(&local_socket, &inbuf)){
	fprintf(stderr, "Read Error During Final Reply: %s!\n",
                        error_message(retval));
	free(send_cksum.contents);
        exit(1);
    }
     
    if ((retval = krb5_rd_priv(&inbuf,
                        &my_creds.keyblock,
                        &foreign_addr,
                        &local_addr,
                        rep_ret->seq_number,
                        KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
                        0,
                        0,
                        &msg_data))) {
	fprintf(stderr, "Error during Final Read Decoding :%s!\n",
                        error_message(retval));
	free(send_cksum.contents);
	free(inbuf.data);
	exit(1);
    }
    free(inbuf.data);

    decode_kadmind_reply(msg_data, &rd_priv_resp);
    free(msg_data.data);
    
    if (!((rd_priv_resp.appl_code == KADMIN) &&
	  (rd_priv_resp.retn_code == KADMGOOD))) {
	if (rd_priv_resp.message)
	    fprintf(stderr, "%s\n", rd_priv_resp.message);
	else
	    fprintf(stderr, "Generic Error During kadmin Termination!\n");
	retval = 1;
    } else {
	fprintf(stderr, "\nHave a Good Day.\n\n");
    }

    if (rd_priv_resp.message)
	free(rd_priv_resp.message);

    free(send_cksum.contents);
    
    exit(retval);
}

krb5_error_code
get_first_ticket(DECLARG(krb5_ccache, cache),
		DECLARG(krb5_principal, client))
OLDDECLARG(krb5_ccache, cache)
OLDDECLARG(krb5_principal, client)
{
    char prompt[255];			/* for the password prompt */
    
    krb5_address **my_addresses;

    char *client_name;
    krb5_error_code retval;
    char *password;
    int  pwsize;
    int	 i;
    
    if ((retval = krb5_unparse_name(client, &client_name))) {
	fprintf(stderr, "Unable to Unparse Client Name!\n");
	return(1);
    }

    if ((retval = krb5_os_localaddr(&my_addresses))) {
	fprintf(stderr, "Unable to Get Principals Address!\n");
	return(1);
    }

    memset((char *) &my_creds, 0, sizeof(my_creds));

    my_creds.client = client;

    if ((retval = krb5_build_principal_ext(&my_creds.server,
                                        client->realm.length, 
					client->realm.data,
                                        strlen(CPWNAME),
					CPWNAME,    /* kadmin */
                                        client->realm.length,
					client->realm.data, 
					   /* instance is <realm> */
                                        0))) {
        fprintf(stderr, "Error %s while building client name!\n");
	krb5_free_addresses(my_addresses);
        return(1);
    }
    
    (void) sprintf(prompt,"Password for %s: ", (char *) client_name);

    if ((password = (char *) calloc (1, 255)) == NULL) {
        fprintf(stderr, "No Memory for Retrieving Admin Password!\n");
        return(1);
    }

    pwsize = 255;
    if ((retval = krb5_read_password(
                                prompt,
                                0,
                                password,
                                &pwsize) || pwsize == 0)) {
	fprintf(stderr, "Error while reading password for '%s'!\n",
                                client_name);
	free(password);
	krb5_free_addresses(my_addresses);
	return(1);
    }

	/*	Build Request for Initial Credentials */
    for (i=0; preauth_search_list[i] >= 0; i++) {
	retval = krb5_get_in_tkt_with_password(
					0,	/* options */
					my_addresses,
					/* do random preauth */
                                        preauth_search_list[i],
					ETYPE_DES_CBC_CRC,   /* etype */
					KEYTYPE_DES,
					password,
					cache,
					&my_creds,
				        0);
	if (retval != KRB5KDC_PREAUTH_FAILED &&
	    retval != KRB5KRB_ERR_GENERIC)
	    break;
    }
    
        /* Do NOT Forget to zap password  */
    memset((char *) password, 0, pwsize);
    free(password);
    krb5_free_addresses(my_addresses);
    
    if (retval) {
            fprintf(stderr, "\nUnable to Get Initial Credentials : %s!\n",
                        error_message(retval));
            return(1);
    }
 
    return(0);
}

krb5_error_code
adm5_init_link( realm_of_server, local_socket)
krb5_data *realm_of_server;
int * local_socket;

{
    struct servent *service_process;	       /* service we will talk to */
    struct hostent *remote_host;	       /* host we will talk to */
    char **hostlist;
    int namelen;
    int i;

    krb5_error_code retval;

    /* clear out the structure first */
    (void) memset((char *)&remote_sin, 0, sizeof(remote_sin));

    if ((service_process = getservbyname(CPW_SNAME, "tcp")) == NULL) {
	fprintf(stderr, "Unable to find Service (%s) Check services file!\n",
		CPW_SNAME);
	return(1);
    }

    		/* Copy the Port Number */
    remote_sin.sin_port = service_process->s_port;

    hostlist = 0;

		/* Identify all Hosts Associated with this Realm */
    if ((retval = krb5_get_krbhst (realm_of_server, &hostlist))) {
        fprintf(stderr, "krb5_get_krbhst: Unable to Determine Server Name!\n");
        return(retval);
    }

    if (hostlist[0] == 0) {
        fprintf(stderr, "No hosts found!\n");
        return KRB5_REALM_UNKNOWN;
    }

    for (i=0; hostlist[i]; i++) {
        remote_host = gethostbyname(hostlist[i]);
        if (remote_host != 0) {

		/* set up the address of the foreign socket for connect() */
	    remote_sin.sin_family = remote_host->h_addrtype;
	    (void) memcpy((char *) &remote_sin.sin_addr, 
			(char *) remote_host->h_addr,
			sizeof(remote_host->h_addr));
	    break;	/* Only Need one */
	}
    }

    krb5_free_krbhst(hostlist);

    /* open a TCP socket */
    *local_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (*local_socket < 0) {
	retval = errno;
	fprintf(stderr, "Cannot Open Socket!\n");
	return retval;
    }
    /* connect to the server */
    if (connect(*local_socket, &remote_sin, sizeof(remote_sin)) < 0) {
	retval = errno;
	fprintf(stderr, "Cannot Connect to Socket!\n");
	close(*local_socket);
	return retval;
    }

    /* find out who I am, now that we are connected and therefore bound */
    namelen = sizeof(local_sin);
    if (getsockname(*local_socket, 
		(struct sockaddr *) &local_sin, &namelen) < 0) {
	retval = errno;
	fprintf(stderr, "Cannot Perform getsockname!\n");
	close(*local_socket);
	return retval;
    }
	return 0;
}

void
get_def_princ(client)
     krb5_principal *client;
{
    krb5_ccache cache = NULL;
    struct passwd *pw;
    int retval;
    char client_name[755];
    krb5_flags cc_flags;

    /* Identify Default Credentials Cache */
    if (retval = krb5_cc_default(&cache)) {
	fprintf(stderr, "Error while getting default ccache!\n");
	exit(1);
    }
    
    /*
     * 	Attempt to Modify Credentials Cache 
     *		retval == 0 ==> ccache Exists - Use It 
     * 		retval == ENOENT ==> No Entries, but ccache Exists 
     *		retval != 0 ==> Assume ccache does NOT Exist 
     */
    cc_flags = 0;
    if (retval = krb5_cc_set_flags(cache, cc_flags)) {
	/* Search passwd file for client */
	pw = getpwuid((int) getuid());
	if (pw) {
	    (void) strcpy(client_name, pw->pw_name);
	    if (!strncmp("root", client_name, strlen(client_name))) {
		fprintf(stderr,
			"root is not a valid Adimnistrator\n!\n");
		usage();
	    }
	} else {
	    fprintf(stderr, 
		    "Unable to Identify Principal from Password File!\n");
	    retval = 1;
	    usage();
	}
	
	/* Use this to get default_realm and format client_name */
	if ((retval = krb5_parse_name(client_name, client))) {
	    fprintf(stderr, "Unable to Parse Client Name!\n");
	    usage();
	}
    } else {
	/* Read Client from Cache */
	if (retval = krb5_cc_get_principal(cache, client)) {
	    fprintf(stderr, 
		    "Unable to Read Principal Credentials File!\n");
	    exit(1);
	}
	
	if (!strncmp("root", (*client)->data[0].data, 
		     (*client)->data[0].length)) {
	    fprintf(stderr, "root is not a valid Administrator\n!\n");
	    usage();
	}
	
	(void) krb5_cc_close(cache);
    }
}

usage()
{
    fprintf(stderr, "Usage:	");
    fprintf(stderr, "kadmin [-n] [Administrator name]\n\n");
    fprintf(stderr, "	If an Administrator name is not supplied, kadmin ");
    fprintf(stderr, "will first\n	attempt to locate the name from ");
    fprintf(stderr, "the default ticket file, then\n	by using the ");
    fprintf(stderr, "username from the 'passwd' file.\n\n");
    fprintf(stderr, "	For Cross Realm Obtain a ticket for 'Administrator ");
    fprintf(stderr, "name' in the\n	Destination realm or ");
    fprintf(stderr, "specify the Destination Realm\n	as part of the ");
    fprintf(stderr, "Administrator name option.\n\n");
    fprintf(stderr, "	Note: If the Administrator Name is not ");
    fprintf(stderr, "supplied, then the \n");
    fprintf(stderr, "	'/admin' instance will be appended to the ");
    fprintf(stderr, "default name unless\n");
    fprintf(stderr, "	the -n option is used.\n\n");
    exit(0);
}

void decode_kadmind_reply(data, response)
    krb5_data	data;
    kadmin_requests	*response;
{
    response->appl_code = data.data[0];
    response->oper_code = data.data[1];
    response->retn_code = data.data[2];
    if (data.length > 3 && data.data[3]) {
	response->message = malloc(data.length - 2);
	if (response->message) {
	    memcpy(response->message, data.data + 3, data.length - 3);
	    response->message[data.length - 3] = 0;
	}
    } else
	response->message = NULL;

    return;
}

int print_status_message(response, success_msg)
    kadmin_requests	*response;
    char		*success_msg;
{
    int	retval = 1;
    
    if (response->appl_code == KADMIN) {
	if (response->retn_code == KADMGOOD) {
	    fprintf(stderr, "%s\n", success_msg);
	    retval = 0;
	} else if (response->retn_code == KADMBAD) 
	    fprintf(stderr, "%s\n", response->message);
	else
	    fprintf(stderr, "ERROR: unknown return code from server.\n");
    } else
	fprintf(stderr, "ERROR: unknown application code from server.\n");

    if (response->message)
	free(response->message);
    
    return retval;
}    
