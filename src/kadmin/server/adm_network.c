/*
 * kadmin/server/adm_network.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Network Initialization/Shutdown Component of the 
 * Version 5 Administration network
 */

/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */


/*
 *   adm_network.c
 */

#include <stdio.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <signal.h>

#ifndef sigmask
#define sigmask(m)    (1 <<((m)-1))
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif
#include <netdb.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/adm_defs.h>
#include "adm_extern.h"

extern int errno;

#ifdef POSIX_SIGTYPE
#define SIGNAL_RETURN return
#else
#define SIGNAL_RETURN return(0)
#endif

krb5_error_code
closedown_network(prog)
const char *prog;
{
    if (client_server_info.server_socket == -1) return(1);

    (void) close(client_server_info.server_socket);
    client_server_info.server_socket = -1;
    return(0);
}

krb5_sigtype
doexit()
{
    exit_now = 1;
    SIGNAL_RETURN;
}

/*
 *  SIGCHLD brings us here
 */
krb5_sigtype
do_child()
{
    /*
     *  <sys/param.h> has been included, so BSD will be defined on
     * BSD systems
     */
#if BSD > 0 && BSD <= 43
#ifndef WEXITSTATUS
#define	WEXITSTATUS(w)	(w).w_retcode
#define WTERMSIG(w)	(w).w_termsig
#endif
    union wait	status;
#else
    int	status;
#endif
    int pid, i, j;

    signal(SIGCHLD, do_child);
    
    pid = wait(&status);
    if (pid < 0)
	SIGNAL_RETURN;
 
    for (i = 0; i < pidarraysize; i++)
	if (pidarray[i] == pid) {
			/* found it */
		for (j = i; j < pidarraysize-1; j++)
			/* copy others down */
			pidarray[j] = pidarray[j+1];
		pidarraysize--;
		if ( !WIFEXITED(status) ) {
			com_err("adm_network", 0, "child %d: termsig %d", 
				pid, WTERMSIG(status) );
			com_err("adm_network", 0, "retcode %d", 
				WEXITSTATUS(status));
		}

		SIGNAL_RETURN;
	}

    com_err("adm_network", 0, 
	"child %d not in list: termsig %d, retcode %d", pid,
	WTERMSIG(status), WEXITSTATUS(status));

    SIGNAL_RETURN;
}

krb5_error_code
setup_network(prog)
const char *prog;
{
    krb5_error_code retval;
    char server_host_name[MAXHOSTNAMELEN];
    char *lrealm;
    krb5_sigtype     doexit(), do_child();
    struct servent *service_servent;
    struct hostent *service_hostent;

    signal(SIGINT, doexit);
    signal(SIGTERM, doexit);
    signal(SIGHUP, doexit);
    signal(SIGQUIT, doexit);
    signal(SIGPIPE, SIG_IGN); /* get errors on write() */
    signal(SIGALRM, doexit);
    signal(SIGCHLD, do_child);
 
    client_server_info.name_of_service = malloc(768);
    if (!client_server_info.name_of_service) {
        com_err("setup_network", 0, 
		"adm_network: No Memory for name_of_service");
        return ENOMEM;
    }

   
    if (retval = krb5_get_default_realm(&lrealm)) {
        free(client_server_info.name_of_service);
	com_err( "setup_network", 0, 
		"adm_network: Unable to get Default Realm");
	return retval;
    }

    (void) sprintf(client_server_info.name_of_service, "%s%s%s%s%s",
                        CPWNAME, "/", lrealm, "", "");
    free(lrealm);

#ifdef DEBUG
    fprintf(stderr, "client_server_info.name_of_service = %s\n",
		client_server_info.name_of_service);
#endif	/* DEBUG */

    if ((retval = krb5_parse_name(client_server_info.name_of_service,
                        &client_server_info.server))) {
        free(client_server_info.name_of_service);
	com_err( "setup_network", retval, 
		"adm_network: Unable to Parse Server Name");
	return retval;
    }

    if (gethostname(server_host_name, sizeof(server_host_name))) {
	retval = errno;
        krb5_free_principal(client_server_info.server);
        free(client_server_info.name_of_service);
	com_err( "setup_network", retval,
		"adm_network: Unable to Identify Who I am");
	return retval;
    }

    service_hostent = gethostbyname(server_host_name);
    if (!service_hostent) {
	retval = errno;
        free(client_server_info.name_of_service);
	com_err("setup_network", retval, "adm_network: Failed gethostname");
	return retval;
    }

#ifdef DEBUG
    fprintf(stderr, "Official host name = %s\n", service_hostent->h_name);
#endif	/* DEBUG */

    client_server_info.server_name.sin_family = AF_INET;

#ifdef unicos61
    memcpy((char *) &client_server_info.server_name.sin_addr,
		(char *) service_hostent->h_addr, service_hostent->h_length);
#else
    memcpy((char *) &client_server_info.server_name.sin_addr.s_addr,
		(char *) service_hostent->h_addr, service_hostent->h_length);
#endif /* unicos61 */

    client_server_info.server_socket = -1;

#ifdef DEBUG
    fprintf(stderr, "adm5_tcp_portname = %s\n", adm5_tcp_portname);
#endif	/* DEBUG */

    service_servent = getservbyname(adm5_tcp_portname, "tcp");

    if (!service_servent) {
        krb5_free_principal(client_server_info.server);
        free(client_server_info.name_of_service);
	com_err("setup_network", 0, "adm_network: %s/tcp service unknown", 
			adm5_tcp_portname);
	return(1);
    }

#ifdef DEBUG
    fprintf(stderr, "Official service name = %s\n", service_servent->s_name);
#endif	/* DEBUG */

    client_server_info.server_name.sin_port =  service_servent->s_port;

    if ((client_server_info.server_socket = 
		socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	retval = errno;
        krb5_free_principal(client_server_info.server);
        free(client_server_info.name_of_service);
	com_err("setup_network", retval, 
		"adm_network: Cannot create server socket.");
	return(1);
    }

#ifdef DEBUG
    fprintf(stderr, "Socket File Descriptor = %d\n", 
		client_server_info.server_socket);
    fprintf(stderr, "sin_family = %d\n", 
		client_server_info.server_name.sin_family);
    fprintf(stderr, "sin_port = %d\n", 
		client_server_info.server_name.sin_port);
    fprintf(stderr, "in_addr.s_addr = %s\n", 
		inet_ntoa( client_server_info.server_name.sin_addr ));
#endif	/* DEBUG */

    if (bind(client_server_info.server_socket,
		&client_server_info.server_name, 
		sizeof(client_server_info.server_name)) < 0) {
	retval = errno;
        krb5_free_principal(client_server_info.server);
        free(client_server_info.name_of_service);
	com_err("setup_network", retval, 
		"adm_network: Cannot bind server socket.");
	return(1);
    }

    return(0);
}
