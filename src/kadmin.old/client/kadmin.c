/*
 * kadmin/client/kadmin.c
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
 * kadmin
 * Perform Remote Kerberos Administrative Functions
 */

#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include "com_err.h"

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif

#include "krb5.h"
#include "adm_defs.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc(), *calloc(), *realloc();
#endif

static krb5_error_code get_first_ticket 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ccache, 
		   krb5_principal,
		   krb5_creds *));

struct sockaddr_in local_sin, remote_sin;

char cache_name[255] = "";

static void get_def_princ
	KRB5_PROTOTYPE((krb5_context,
     		   krb5_principal * ));

void decode_kadmind_reply();
int print_status_message();
extern char *optarg;
extern int optind;


void
main(argc,argv)
  int argc;
  char *argv[];
{
    krb5_ccache cache = NULL;

    krb5_address local_addr, foreign_addr;

    krb5_principal client;

    char *client_name;	/* Single string representation of client id */

    krb5_data *requested_realm;
    krb5_creds my_creds;

    krb5_error_code retval;	/* return code */

    int local_socket;

    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;

    kadmin_requests rd_priv_resp;

    krb5_context context;
    krb5_data msg_data, inbuf;
    char buffer[255];
    char command_type[120];
    char princ_name[120];
    int i, valid;
    int option;
    int oper_type;
    int nflag = 0;
    int port = 0;

    krb5_auth_context new_auth_context;
    krb5_replay_data replaydata;

    krb5_init_context(&context);
    krb5_init_ets(context);

    while ((option = getopt(argc, argv, "c:np:")) != EOF) {
	switch (option) {
	  case 'c':
	    strcpy (cache_name, optarg);
	    break;
	  case 'n':
	    nflag++;
	    break;
	  case 'p':
	    port = htons(atoi(optarg));
	    break;
	  case '?':
	  default:
	    usage();
	    break;
	}
    }
    
    if (optind < argc) {
	/* Admin name specified on command line */
	client_name = (char *) malloc(755);
	memset((char *) client_name, 0, sizeof(client_name));
	strcpy(client_name, argv[optind++]);
	if (retval = krb5_parse_name(context, client_name, &client)) {
	    fprintf(stderr, "Error Parsing %s\n", client_name);
	    usage();
	}
    }
    else {
	/* Admin name should be defaulted */
	get_def_princ(context, &client);
	if (retval = krb5_unparse_name(context, client, &client_name)) {
	    fprintf(stderr, "Unable to unparse default administrator name!\n");
	    usage();
	}
    }

    /* At this point, both client and client_name are set up. */

    if (!nflag) {
	free(client_name);
	client_name = (char *) malloc(755);
	strcpy(client_name, client->data[0].data);
	strncat(client_name, "/admin@", 7);
	strncat(client_name, client->realm.data, client->realm.length);
	krb5_free_principal(context, client);
	if (retval = krb5_parse_name(context, client_name, &client)) {
	    fprintf(stderr, "Unable to Parse %s\n", client_name);
	    usage();
	}
    }

    if (optind < argc)
	usage();

	/* Create credential cache for kadmin */
    if (!cache_name[0])
        (void) sprintf(cache_name, "FILE:/tmp/tkt_adm_%d", getpid());

    if ((retval = krb5_cc_resolve(context, cache_name, &cache))) {
	fprintf(stderr, "Unable to Resolve Cache: %s!\n", cache_name);
    }
    
    if ((retval = krb5_cc_initialize(context, cache, client))) {
        fprintf(stderr, "Error initializing cache: %s!\n", cache_name);
        exit(1);
    }
 
/*
 *	Verify User by Obtaining Initial Credentials prior to Initial Link
 */

    if ((retval = get_first_ticket(context, cache, client, &my_creds))) {
        (void) krb5_cc_destroy(context, cache);
	exit(1);
    }
    /* my_creds has the necessary credentials for further processing:
       Destroy credential cache for security reasons */
    (void) krb5_cc_destroy(context, cache);
    
    requested_realm = (krb5_data *) &client->realm;


	/* Initiate Link to Server */
    if ((retval = adm5_init_link(context, requested_realm, port,
				 &local_socket))) {
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

	retval = krb5_net_write(context, local_socket, (char *) &msg_length + 2, 2);
	if (retval < 0) {
	    fprintf(stderr, "krb5_net_write failure!\n");
            (void) krb5_cc_destroy(context, cache);
	    exit(1);
	}
    }

    local_addr.addrtype = ADDRTYPE_INET;
    local_addr.length = SIZEOF_INADDR ;
    local_addr.contents = (krb5_octet *) &local_sin.sin_addr;

    foreign_addr.addrtype = ADDRTYPE_INET;
    foreign_addr.length = SIZEOF_INADDR ;
    foreign_addr.contents = (krb5_octet *) &remote_sin.sin_addr;

    krb5_auth_con_init(context, &new_auth_context);
    krb5_auth_con_setflags(context, new_auth_context,
                           KRB5_AUTH_CONTEXT_RET_SEQUENCE);
  
    krb5_auth_con_setaddrs(context, new_auth_context,
                           &local_addr, &foreign_addr);

    /* call Kerberos library routine to obtain an authenticator,
       pass it over the socket to the server, and obtain mutual
       authentication. */

    inbuf.data = ADM5_ADM_VERSION;
    inbuf.length = strlen(ADM5_ADM_VERSION);

    if ((retval = krb5_sendauth(context, &new_auth_context,
			(krb5_pointer) &local_socket,
			ADM_CPW_VERSION, 
			my_creds.client, 
			my_creds.server,
			AP_OPTS_MUTUAL_REQUIRED,
			&inbuf,
			&my_creds,           
			0,
			&err_ret,
			&rep_ret, 
			NULL))) {
	fprintf(stderr, "Error while performing sendauth: %s!\n",
			error_message(retval));
	exit(1);
    }

	/* Read back what the server has to say ... */
    if (retval = krb5_read_message(context, &local_socket, &inbuf)){
	fprintf(stderr, " Read Message Error: %s!\n",
			error_message(retval));
        exit(1);
    }

    if ((inbuf.length != 2) || (inbuf.data[0] != KADMIND) ||
			(inbuf.data[1] != KADMSAG)){
	fprintf(stderr, " Invalid ack from admin server.!\n");
        exit(1);
    }
    free(inbuf.data);

    if ((inbuf.data = (char *) calloc(1, 2)) == (char *) 0) {
	fprintf(stderr, "No memory for command!\n");
        exit(1);
    }

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = 0xff;
    inbuf.length = 2;

    if ((retval = krb5_mk_priv(context, new_auth_context, &inbuf,
			       &msg_data, &replaydata))) {
	fprintf(stderr, "Error during First Message Encoding: %s!\n",
			error_message(retval));
	free(inbuf.data);
        exit(1);
    }
    free(inbuf.data);

		/* write private message to server */
    if (krb5_write_message(context, &local_socket, &msg_data)){
	fprintf(stderr, "Write Error During First Message Transmission!\n");
        exit(1);
    } 
    free(msg_data.data);

    for ( ; ; ) {
		/* Ok Now let's get the private message */
	if (retval = krb5_read_message(context, &local_socket, &inbuf)){
	    fprintf(stderr, "Read Error During First Reply: %s!\n",
			error_message(retval));
            exit(1);
	}

	if ((retval = krb5_rd_priv(context, new_auth_context, &inbuf,
				   &msg_data, &replaydata))) {
	    fprintf(stderr, "Error during First Read Decoding: %s!\n", 
			error_message(retval));
            exit(1);
	}
	free(inbuf.data);
	free(msg_data.data);

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
	    if (retval = kadm_add_user(context, new_auth_context, &my_creds, 
				       &local_socket, oper_type, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "cpw")) {
	    valid++;
	    oper_type = CHGOPER;
	    if (retval = kadm_cpw_user(context, new_auth_context, &my_creds, 
				       &local_socket, oper_type, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "addrnd")) {
	    valid++;
	    if (retval = kadm_add_user_rnd(context, new_auth_context, &my_creds,
					   &local_socket, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "cpwrnd")) {
	    valid++;
	    if (retval = kadm_cpw_user_rnd(context, new_auth_context, &my_creds, 
					   &local_socket, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "del")) {
	    valid++;
	    if (retval = kadm_del_user(context, new_auth_context, &my_creds, 
				       &local_socket, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "inq")) {
	    valid++;
	    if (retval = kadm_inq_user(context, new_auth_context, &my_creds, 
				       &local_socket, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "mod")) {
	    valid++;
	    if (retval = kadm_mod_user(context, new_auth_context, &my_creds, 
				       &local_socket, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "addv4")) {
	    valid++;
	    oper_type = AD4OPER;
	    if (retval = kadm_add_user(context, new_auth_context, &my_creds, 
				       &local_socket, oper_type, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "cpwv4")) {
	    valid++;
	    oper_type = CH4OPER;
	    if (retval = kadm_cpw_user(context, new_auth_context, &my_creds, 
				       &local_socket, oper_type, princ_name)) 
	    break;
	}
	if (!strcmp(command_type, "q")) { 
	    valid++;
	    retval = kadm_done(context, new_auth_context, &my_creds, 
			       &local_socket); 
	    break;
	}
	
	if (!valid) {
	    fprintf(stderr, "Invalid Input - Retry\n");
	    goto repeat;
	}
    }

    if (retval) {
        exit(1);
    }

    		/* Ok Now let's get the final private message */
    if (retval = krb5_read_message(context, &local_socket, &inbuf)){
	fprintf(stderr, "Read Error During Final Reply: %s!\n",
                        error_message(retval));
        exit(1);
    }
     
    if ((retval = krb5_rd_priv(context, new_auth_context, &inbuf,
                               &msg_data, &replaydata))) {
	fprintf(stderr, "Error during Final Read Decoding :%s!\n",
                        error_message(retval));
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

    krb5_free_principal(context, client);
    
    exit(retval);
}

static krb5_error_code
get_first_ticket(context, cache, client, my_creds)
    krb5_context context;
    krb5_ccache cache;
    krb5_principal client;
    krb5_creds * my_creds;
{
    char prompt[255];			/* for the password prompt */
    
    krb5_address **my_addresses;

    char *client_name;
    krb5_error_code retval;
    char *password;
    int  pwsize;
    int	 i;
    
    if ((retval = krb5_unparse_name(context, client, &client_name))) {
	fprintf(stderr, "Unable to Unparse Client Name!\n");
	return(1);
    }

    if ((retval = krb5_os_localaddr(context, &my_addresses))) {
	free(client_name);
	fprintf(stderr, "Unable to Get Principals Address!\n");
	return(1);
    }

    memset((char *) my_creds, 0, sizeof(krb5_creds));

    my_creds->client = client;

    if ((retval = krb5_build_principal_ext(context, &my_creds->server,
                                        client->realm.length, 
					client->realm.data,
                                        strlen(CPWNAME),
					CPWNAME,    /* kadmin */
                                        client->realm.length,
					client->realm.data, 
					   /* instance is <realm> */
                                        0))) {
        fprintf(stderr, "Error %s while building client name!\n",
		error_message(retval));
	krb5_free_addresses(context, my_addresses);
	free(client_name);
        return(1);
    }
    
    (void) sprintf(prompt,"Password for %s: ", (char *) client_name);

    if ((password = (char *) calloc (1, 255)) == NULL) {
        fprintf(stderr, "No Memory for Retrieving Admin Password!\n");
	free(client_name);
        return(1);
    }

    pwsize = 255;
    if ((retval = krb5_read_password(context, 
                                prompt,
                                0,
                                password,
                                &pwsize) || pwsize == 0)) {
	fprintf(stderr, "Error while reading password for '%s'!\n",
                                client_name);
	free(password);
	krb5_free_addresses(context, my_addresses);
	free(client_name);
	return(1);
    }

	/*	Build Request for Initial Credentials */
    retval = krb5_get_in_tkt_with_password(context, 0, /* options */
					my_addresses,
                                        NULL, /* Default encryption list */
                                        NULL, /* Default preauth list */
					password, cache, my_creds, 0);
    
        /* Do NOT Forget to zap password  */
    memset((char *) password, 0, pwsize);
    free(password);
    krb5_free_addresses(context, my_addresses);
    free(client_name);
    
    if (retval) {
            fprintf(stderr, "\nUnable to Get Initial Credentials: %s!\n",
                        error_message(retval));
            return(1);
    }
 
    return(0);
}

krb5_error_code
adm5_init_link(context, realm_of_server, port, local_socket)
    krb5_context context;
    krb5_data *realm_of_server;
    int port;
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

    if (port != 0) {
        remote_sin.sin_port = port;
    } else {
	if ((service_process = getservbyname(CPW_SNAME, "tcp")) == NULL) {
	    fprintf(stderr, "Unable to find Service (%s) Check services file!\n",
		    CPW_SNAME);
	    return(1);
	}

		    /* Copy the Port Number */
	remote_sin.sin_port = service_process->s_port;
    }

    hostlist = 0;

		/* Identify all Hosts Associated with this Realm */
    if ((retval = krb5_get_krbhst (context, realm_of_server, &hostlist))) {
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

    krb5_free_krbhst(context, hostlist);

    /* open a TCP socket */
    *local_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (*local_socket < 0) {
	retval = errno;
	fprintf(stderr, "Cannot Open Socket!\n");
	return retval;
    }
    /* connect to the server */
    if (connect(*local_socket, (struct sockaddr *) &remote_sin, sizeof(remote_sin)) < 0) {
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

static void
get_def_princ(context, client)
     krb5_context context;
     krb5_principal *client;
{
    krb5_ccache cache = NULL;
    struct passwd *pw;
    int retval;
    char client_name[755];
    krb5_flags cc_flags;

    /* Identify Default Credentials Cache */
    if (retval = krb5_cc_default(context, &cache)) {
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
    if (retval = krb5_cc_set_flags(context, cache, cc_flags)) {
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
	if ((retval = krb5_parse_name(context, client_name, client))) {
	    fprintf(stderr, "Unable to Parse Client Name!\n");
	    usage();
	}
    } else {
	/* Read Client from Cache */
	if (retval = krb5_cc_get_principal(context, cache, client)) {
	    fprintf(stderr, 
		    "Unable to Read Principal Credentials File!\n");
	    exit(1);
	}
	
	if (!strncmp("root", (*client)->data[0].data, 
		     (*client)->data[0].length)) {
	    fprintf(stderr, "root is not a valid Administrator\n!\n");
	    usage();
	}
    }
    (void) krb5_cc_close(context, cache);
}

usage()
{
    fprintf(stderr, "Usage:	");
    fprintf(stderr, "kadmin [-n] [-p port] [Administrator name]\n\n");
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
	response->message = (char *)malloc(data.length - 2);
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
