/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * added kerberos authentication (tom coppeto, 1/15/91)
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)pop_init.c  1.12    8/16/90";
#endif not lint

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
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <com_err.h>
#include <ctype.h>
krb5_principal ext_client;
char *client_name;
#endif /* KRB5 */
#endif /* KERBEROS */
#ifdef BIND43
#include <arpa/nameser.h>
#include <resolv.h>
#endif

extern int      errno;

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
    int standalone = 0;
    int                     c;
    int                     len;
    extern char         *   optarg;
    int                     options = 0;
    int                     sp = 0;             /*  Socket pointer */
    char                *   trace_file_name;

    /*  Initialize the POP parameter block */
    bzero ((char *)p,(int)sizeof(POP));

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
    while ((c = getopt(argcount,argmessage,"dst:")) != EOF)
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
                    pop_log(p,POP_ERROR,
                        "Unable to open trace file \"%s\", err = %d",
                            optarg,errno);
                    exit(-1);
                }
                trace_file_name = optarg;
                break;
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
	if (!(spr = getservbyname("kpop", "tcp"))) {
	    syslog(LOG_ERR, "kpop/tcp: unknown service");
	    exit(3);
	}
#else
	if (!(spr = getservbyname("pop", "tcp"))) {
	    syslog(LOG_ERR, "kpop/tcp: unknown service");
	    exit(3);
	}
#endif
	sin.sin_port = spr->s_port;
	if (bind(sock, &sin, sizeof(sin))) {
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
        pop_log(p,POP_ERROR,
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
            "%s: unable to get canonical name of client, err = %d", 
		p->ipaddr, errno);
        p->client = p->ipaddr;
    }
    /*  Save the cannonical name of the client host in 
        the POP parameter block */
    else {

#ifndef BIND43
        p->client = ch->h_name;
#else

        /*  Distrust distant nameservers */
        extern struct state     _res;
        struct hostent      *   ch_again;
        char            *   *   addrp;

        /*  We already have a fully-qualified name */
        _res.options &= ~RES_DEFNAMES;

        /*  See if the name obtained for the client's IP 
            address returns an address */
        if ((ch_again = gethostbyname(ch->h_name)) == NULL) {
	  pop_log(p,POP_PRIORITY,
                "%s: resolves to an unknown host name \"%s\".",
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
                if (bcmp(*addrp,&(cs.sin_addr),sizeof(cs.sin_addr)) == 0) break;

            if (!*addrp) {
                pop_log (p,POP_PRIORITY,
			 "%s: not listed for its host name \"%s\".",
			 p->ipaddr,ch->h_name);
                p->client = p->ipaddr;
            }
        }
#endif BIND43
    }

    /*  Create input file stream for TCP/IP communication */
    if ((p->input = fdopen(sp,"r")) == NULL){
        pop_log(p,POP_ERROR,
            "%s: unable to open communication stream for input, err = %d",
		p->client, errno);
        exit (-1);
    }

    /*  Create output file stream for TCP/IP communication */
    if ((p->output = fdopen(sp,"w")) == NULL){
      pop_log(p,POP_ERROR,
	      "%s: unable to open communication stream for output, err = %d",
	      p->client, errno);
        exit (-1);
    }

    pop_log(p,POP_INFO,
        "%s: (v%s) Servicing request at %s\n", p->client, VERSION, p->ipaddr);

#ifdef DEBUG
    if (p->trace)
        pop_log(p,POP_PRIORITY,
            "Tracing session and debugging information in file \"%s\"",
                trace_file_name);
    else if (p->debug)
        pop_log(p,POP_PRIORITY,"Debugging turned on");
#endif DEBUG
    
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

#endif /* KRB4 */
#ifdef KRB5
    krb5_error_code retval;
    krb5_data aserver[3], *server[4];
    char *remote_host, *def_realm;
    register char *cp;
    struct hostent *hp;
    extern struct state     _res;
    int sock = 0;			/* socket fd # */

    krb5_init_ets();

    if (retval = krb5_get_default_realm(&def_realm)) {
	pop_msg(p, POP_FAILURE, "server mis-configured, no local realm--%s",
		error_message(retval));
	pop_log(p, POP_WARNING,  "%s: mis-configured, no local realm--%s",
		p->client, error_message(retval));
	exit(-1);
    }
#ifdef BIND43
    /*undo some damage*/
    _res.options |= RES_DEFNAMES;
#endif

    if (!(hp = gethostbyname(p->myhost))) {
	pop_msg(p, POP_FAILURE,
		"server mis-configured, can't resolve its own name.");
	pop_log(p, POP_WARNING, "%s: can't resolve hostname '%s'",
		p->client, p->myhost);
	exit(-1);
    }
    /* copy the hostname into non-volatile storage */
    remote_host = malloc(strlen(hp->h_name) + 1);
    (void) strcpy(remote_host, hp->h_name);

    /* lower-case to get name for "instance" part of service name */
    for (cp = remote_host; *cp; cp++)
	if (isupper(*cp))
	    *cp = tolower(*cp);

    aserver[0].length = strlen(def_realm);
    aserver[0].data = def_realm;
    aserver[1].length = strlen("pop");
    aserver[1].data = "pop";
    aserver[2].length = strlen(remote_host);
    aserver[2].data = remote_host;
    server[0] = &aserver[0];
    server[1] = &aserver[1];
    server[2] = &aserver[2];
    server[3] = 0;

    if (retval = krb5_recvauth((krb5_pointer)&sock,
			       "KPOPV1.0",
			       server,
			       0,	/* ignore peer address */
			       0, 0, 0,	/* no fetchfrom, keyproc or arg */
			       0,	/* default rc type */
			       0,	/* don't need seq number */
			       &ext_client,
			       0, 0	/* don't care about ticket or
					   authenticator */
			       )) {
	pop_msg(p, POP_FAILURE, "recvauth failed--%s", error_message(retval));
	pop_log(p, POP_WARNING, "%s: recvauth failed--%s",
		p->client, error_message(retval));
	exit(-1);
    }
    if (retval = krb5_unparse_name(ext_client, &client_name)) {
	pop_msg(p, POP_FAILURE, "name not parsable--%s",
		error_message(retval));
	pop_log(p, POP_DEBUG, "name not parsable (%s)",
		inet_ntoa(addr->sin_addr));
	exit(-1);
    }
#ifdef DEBUG
    pop_log(p, POP_DEBUG, "%s (%s): ok", client_name, inet_ntoa(addr->sin_addr));
#endif /* DEBUG */

#endif /* KRB5 */
#endif /* KERBEROS */

    return(POP_SUCCESS);
}
