/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "popper.h"

#ifdef KERBEROS
#ifdef KRB4
#ifdef KRB5
 #error you can only use one of KRB4, KRB5
#endif
#include <krb.h>
AUTH_DAT kdata;
#endif /* KRB4 */
#ifdef KRB5    
#include "krb5.h"
#include "com_err.h"
#include <ctype.h>
krb5_principal ext_client;
krb5_context pop_context;
char *client_name;
#endif /* KRB5 */
#endif /* KERBEROS */

/* 
 *  init:   Start a Post Office Protocol session
 */

pop_init(p,argcount,argmessage)
POP     *       p;
int             argcount;
char    **      argmessage;
{

    struct sockaddr_in      cs;                 /*  Communication parameters */
    struct hostent      *   ch;                 /*  Client host information */
    int                     errflag = 0;
    int                     c;
    int                     len;
    extern char         *   optarg;
    int                     options = 0;
    int                     sp = 0;             /*  Socket pointer */
    char                *   trace_file_name;
    int                     standalone = 0;

    /*  Initialize the POP parameter block */
    memset ((char *)p, 0, (int)sizeof(POP));

    /*  Save my name in a global variable */
    p->myname = argmessage[0];

    /*  Get the name of our host */
    (void)gethostname(p->myhost,MAXHOSTNAMELEN);

    /*  Open the log file */
#ifdef SYSLOG42
    (void)openlog(p->myname,0);
#else
    (void)openlog(p->myname,POP_LOGOPTS,POP_FACILITY);
#endif

    /*  Process command line arguments */
    while ((c = getopt(argcount,argmessage,"dt:s")) != EOF)
        switch (c) {

            /*  Debugging requested */
            case 'd':
                p->debug++;
                options |= SO_DEBUG;
                break;

            /*  Debugging trace file specified */
            case 't':
                p->debug++;
                if ((p->trace = fopen(optarg,"a+")) == NULL) {
                    pop_log(p,POP_PRIORITY,
                        "Unable to open trace file \"%s\", err = %d",
                            optarg,errno);
                    exit(-1);
                }
                trace_file_name = optarg;
                break;

	    /* Standalone operation */
	    case 's':
		standalone++;
		break;

            /*  Unknown option received */
            default:
                errflag++;
        }

    /*  Exit if bad options specified */
    if (errflag) {
        (void)fprintf(stderr,"Usage: %s [-d]\n",argmessage[0]);
        exit(-1);
    }

    if (standalone) {
	int acc, sock;
	struct sockaddr_in sin;
	struct servent *spr;

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	    syslog(LOG_ERR, "socket: %m");
	    exit(3);
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = 0;

#ifdef KERBEROS
#ifndef KPOP_SERVICE
#define KPOP_SERVICE "kpop"
#endif
	if (!(spr = getservbyname(KPOP_SERVICE, "tcp"))) {
	    syslog(LOG_ERR, "%s/tcp: unknown service", KPOP_SERVICE);
	    exit(3);
	}
#else
	if (!(spr = getservbyname("pop", "tcp"))) {
	    syslog(LOG_ERR, "pop/tcp: unknown service");
	    exit(3);
	}
#endif
	sin.sin_port = spr->s_port;
	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin))) {
	    syslog(LOG_ERR, "bind: %m");
	    exit(3);
	}
	if (listen(sock, 1) == -1) {
	    syslog(LOG_ERR, "listen: %m");
	    exit(3);
	}
	len = sizeof(cs);
	if ((acc = accept(sock, (struct sockaddr *)&cs, &len)) == -1) {
	    syslog(LOG_ERR, "accept: %m");
	    exit(3);
	}
	dup2(acc, sp);
	close(sock);
	close(acc);
    }

    /*  Get the address and socket of the client to whom I am speaking */
    len = sizeof(cs);
    if (getpeername(sp,(struct sockaddr *)&cs,&len) < 0){
        pop_log(p,POP_PRIORITY,
            "Unable to obtain socket and address of client, err = %d",errno);
        exit(-1);
    }

    /*  Save the dotted decimal form of the client's IP address 
        in the POP parameter block */
    p->ipaddr = inet_ntoa(cs.sin_addr);

    /*  Save the client's port */
    p->ipport = ntohs(cs.sin_port);

    /*  Get the canonical name of the host to whom I am speaking */
    ch = gethostbyaddr((char *) &cs.sin_addr, sizeof(cs.sin_addr), AF_INET);
    if (ch == NULL){
        pop_log(p,POP_PRIORITY,
            "Unable to get canonical name of client, err = %d",errno);
        p->client = p->ipaddr;
    }
    /*  Save the cannonical name of the client host in 
        the POP parameter block */
    else {

#ifndef BIND43
        p->client = (char *) ch->h_name;
#else
#       include <arpa/nameser.h>
#       include <resolv.h>

        /*  Distrust distant nameservers */
#if (__RES < 19931104)
        extern struct state     _res;
#endif
        struct hostent      *   ch_again;
        char            *   *   addrp;

        /*  We already have a fully-qualified name */
        _res.options &= ~RES_DEFNAMES;

        /*  See if the name obtained for the client's IP 
            address returns an address */
        if ((ch_again = gethostbyname(ch->h_name)) == NULL) {
            pop_log(p,POP_PRIORITY,
                "Client at \"%s\" resolves to an unknown host name \"%s\"",
                    p->ipaddr,ch->h_name);
            p->client = p->ipaddr;
        }
        else {
            /*  Save the host name (the previous value was 
                destroyed by gethostbyname) */
            p->client = ch_again->h_name;

            /*  Look for the client's IP address in the list returned 
                for its name */
            for (addrp=ch_again->h_addr_list; *addrp; ++addrp)
                if (memcmp(*addrp,&(cs.sin_addr),sizeof(cs.sin_addr)) == 0) break;

            if (!*addrp) {
                pop_log (p,POP_PRIORITY,
                    "Client address \"%s\" not listed for its host name \"%s\"",
                        p->ipaddr,ch->h_name);
                p->client = p->ipaddr;
            }
        }
#endif
    }

    /*  Create input file stream for TCP/IP communication */
    if ((p->input = fdopen(sp,"r")) == NULL){
        pop_log(p,POP_PRIORITY,
            "Unable to open communication stream for input, err = %d",errno);
        exit (-1);
    }

    /*  Create output file stream for TCP/IP communication */
    if ((p->output = fdopen(sp,"w")) == NULL){
        pop_log(p,POP_PRIORITY,
            "Unable to open communication stream for output, err = %d",errno);
        exit (-1);
    }

    pop_log(p,POP_PRIORITY,
        "(v%s) Servicing request from \"%s\" at %s\n",
            VERSION,p->client,p->ipaddr);

#ifdef DEBUG
    if (p->trace)
        pop_log(p,POP_PRIORITY,
            "Tracing session and debugging information in file \"%s\"",
                trace_file_name);
    else if (p->debug)
        pop_log(p,POP_PRIORITY,"Debugging turned on");
#endif

    return(authenticate(p, &cs));
}

authenticate(p, addr)
     POP     *p;
     struct sockaddr_in *addr;
{

#ifdef KERBEROS
#ifdef KRB4
    Key_schedule schedule;
    KTEXT_ST ticket;
    char instance[INST_SZ];  
    char version[9];
    int auth;
  
    strcpy(instance, "*");
    auth = krb_recvauth(0L, 0, &ticket, "pop", instance,
	  	        addr, (struct sockaddr_in *) NULL,
			&kdata, "", schedule, version);
    
    if (auth != KSUCCESS) {
        pop_msg(p, POP_FAILURE, "Kerberos authentication failure: %s", 
		krb_err_txt[auth]);
	pop_log(p, POP_WARNING, "%s: (%s.%s@%s) %s", p->client, 
		kdata.pname, kdata.pinst, kdata.prealm, krb_err_txt[auth]);
        exit(-1);
    }

#ifdef DEBUG
    pop_log(p, POP_DEBUG, "%s.%s@%s (%s): ok", kdata.pname, 
	    kdata.pinst, kdata.prealm, inet_ntoa(addr->sin_addr));
#endif /* DEBUG */

    strcpy(p->user, kdata.pname);
#endif

#ifdef KRB5
    krb5_auth_context auth_context = NULL;
    krb5_error_code retval;
    krb5_principal server;
    krb5_ticket *ticket;
    int sock = 0;

    krb5_init_context(&pop_context);
    krb5_init_ets(pop_context);

    if (retval = krb5_sname_to_principal(pop_context, p->myhost, "pop", 
					 KRB5_NT_SRV_HST, &server)) {
	pop_msg(p, POP_FAILURE,
		"server '%s' mis-configured, can't get principal--%s",
		p->myhost, error_message(retval));
	pop_log(p, POP_WARNING,  "%s: mis-configured, can't get principal--%s",
		p->client, error_message(retval));
	exit(-1);
    }

    if (retval = krb5_recvauth(pop_context, &auth_context, (krb5_pointer)&sock,
			       "KPOPV1.0", server,
			       0, 	/* no flags */
			       NULL,	/* default keytab */
			       &ticket	/* need ticket for client name */
			       )) {
	pop_msg(p, POP_FAILURE, "recvauth failed--%s", error_message(retval));
	pop_log(p, POP_WARNING, "%s: recvauth failed--%s",
		p->client, error_message(retval));
	exit(-1);
    }
    krb5_free_principal(pop_context, server);
    krb5_auth_con_free(pop_context, auth_context);
    if (retval = krb5_copy_principal(pop_context, ticket->enc_part2->client,
				     &ext_client)) {
	pop_msg(p, POP_FAILURE, "unable to copy principal--%s",
		error_message(retval));
	pop_msg(p, POP_FAILURE, "unable to copy principal (%s)",
		inet_ntoa(addr->sin_addr));
	exit(-1);
    }
    krb5_free_ticket(pop_context, ticket);
    if (retval = krb5_unparse_name(pop_context, ext_client, &client_name)) {
	pop_msg(p, POP_FAILURE, "name not parsable--%s",
		error_message(retval));
	pop_log(p, POP_DEBUG, "name not parsable (%s)",
		inet_ntoa(addr->sin_addr));
	exit(-1);
    }
#ifdef DEBUG
    pop_log(p, POP_DEBUG, "%s (%s): ok", client_name, inet_ntoa(addr->sin_addr));
#endif /* DEBUG */

    if (retval= krb5_aname_to_localname(pop_context, ext_client, 
					sizeof(p->user), p->user)) {
	pop_msg(p, POP_FAILURE, "unable to convert aname(%s) to localname --%s",
		client_name,
		error_message(retval));
	pop_log(p, POP_DEBUG, "unable to convert aname to localname (%s)",
		client_name);
	exit(-1);
    }
#endif /* KRB5 */
#endif /* KERBEROS */

    return(POP_SUCCESS);
}
