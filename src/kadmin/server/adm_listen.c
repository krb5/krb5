/*
 * kadmin/server/adm_listen.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Network Listen Loop for the Kerberos Version 5 Administration server
 */

/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */


/*
  adm_listen.c
*/

#ifdef _AIX
#include <sys/select.h>
#endif

#include "k5-int.h"

#include <syslog.h>
#include <signal.h>
#include "com_err.h"

#ifndef sigmask
#define sigmask(m)    (1 <<((m)-1))
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif

#include "adm_extern.h"

int adm_debug_flag = 0;

#ifdef USE_SIGPROCMASK
/* just do it right */
void
kill_children()
{
    int i;
    sigset_t old, new;

    sigemptyset(&old);
    sigemptyset(&new);
    sigaddset(&new,SIGCHLD);
    sigprocmask(SIG_BLOCK, &new, &old);

    for (i = 0; i < pidarraysize; i++) {
	kill(pidarray[i], SIGINT);
	syslog(LOG_AUTH | LOG_INFO, "Killing Admin Child %d", pidarray[i]);
    }

    sigprocmask(SIG_SETMASK, &old, NULL);
}

#else

#ifdef USE_SIGPROCMASK
/* fake sigmask, sigblock, sigsetmask */
#include <signal.h>
#define sigmask(x) (1L<<(x)-1)
#define sigsetmask(x) sigprocmask(SIG_SETMASK,&x,NULL)
static int _fake_sigstore;
#define sigblock(x) (_fake_sigstore=x,sigprocmask(SIG_BLOCK,&_fake_sigstore,0))
#endif

void
kill_children()
{
    register int i;
    int osigmask;

    osigmask = sigblock(sigmask(SIGCHLD));

    for (i = 0; i < pidarraysize; i++) {
	kill(pidarray[i], SIGINT);
	syslog(LOG_AUTH | LOG_INFO, "Killing Admin Child %d", pidarray[i]);
    }

    sigsetmask(osigmask);
    return;
}
#endif /* HAVE_SIGSET */

/* adm5_listen_and_process - listen on the admin servers port for a request */

int
adm5_listen_and_process(context, prog)
    krb5_context context;
    const char *prog;
{
    extern int errno;
    int found;
    fd_set mask, readfds;
    int addrlen;
    krb5_error_code process_client();
    krb5_error_code retval;
    void kill_children();
    int pid;

    (void) listen(client_server_info.server_socket, 1);

    FD_ZERO(&mask);
    FD_SET(client_server_info.server_socket, &mask);

    for (;;) {				/* loop nearly forever */
	if (exit_now) {
		kill_children();
		return(0);
	}

	readfds = mask;
	if ((found = select(client_server_info.server_socket + 1,
				&readfds,
				(fd_set *)0,
				(fd_set *)0, 
				(struct timeval *)0)) == 0)
		continue;			/* no things read */

	if (found < 0) {
		if (errno != EINTR)
			syslog(LOG_AUTH | LOG_INFO, 
				"%s: select: %s", "adm5_listen_and_process", 
				error_message(errno));
		continue;
	}      

	if (FD_ISSET(client_server_info.server_socket, &readfds)) {
		/* accept the conn */
		addrlen = sizeof(client_server_info.client_name);
		if ((client_server_info.client_socket = 
			accept(client_server_info.server_socket, 
			(struct sockaddr *) &client_server_info.client_name,
			&addrlen)) < 0) {
		    syslog(LOG_AUTH | LOG_INFO, "%s: accept: %s", 
				"adm5_listen_and_process", 
				error_message(errno));
		    continue;
		}
		
		if (adm_debug_flag) {
			retval = process_client(context, "adm5_listen_and_process");
			exit(retval);
		}
			
		/* if you want a sep daemon for each server */
		if (!(pid = fork())) { 
			/* child */
			(void) close(client_server_info.server_socket);

			retval = process_client(context, "adm5_listen_and_process");
			exit(retval);
		} else {
			/* parent */
			if (pid < 0) {
				syslog(LOG_AUTH | LOG_INFO, "%s: fork: %s",
					"adm5_listen_and_process", 
					error_message(errno));
				(void) close(client_server_info.client_socket);
				continue;
			}

			/* fork succeded: keep tabs on child */

			(void) close(client_server_info.client_socket);
			if (pidarray) {
				pidarray = (int *) realloc((char *)pidarray, 
					(++pidarraysize) * sizeof(int));
				pidarray[pidarraysize - 1] = pid;
			} else {
				pidarraysize = 1;
				pidarray = 
				  (int *) malloc(pidarraysize *sizeof(int));
				pidarray[0] = pid;
			}
		}
	} else {
		syslog(LOG_AUTH | LOG_INFO, "%s: something else woke me up!",
			"adm5_listen_and_process");
		return(0);
	}
    }
}
