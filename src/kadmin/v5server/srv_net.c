/*
 * kadmin/v5server/srv_net.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * srv_net.c - handle networking functions of the administrative server.
 */
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/wait.h>
#ifdef	USE_PTHREADS
#include <pthread.h>
#endif	/* USE_PTHREADS */

#include "k5-int.h"
#include "com_err.h"
#include "kadm5_defs.h"
#include "adm.h"

#define	MAX_BIND_TRIES	5

/*
 * This module can use the pthreads library.  To do so, define USE_PTHREADS.
 * You'll need to find out what else pthreads requires (e.g. -lmach -lc_r
 * under OSF/1).
 */
#ifdef	USE_PTHREADS
#define	net_slave_type	pthread_t *
#ifndef	MAX_SLAVES
#define	MAX_SLAVES	SOMAXCONN
#endif	/* MAX_SLAVES */
#else	/* USE_PTHREADS */
#define	net_slave_type	pid_t
#ifndef	MAX_SLAVES
#define	MAX_SLAVES	SOMAXCONN
#endif	/* MAX_SLAVES */
#endif	/* USE_PTHREADS */
#define	NET_SLAVE_FULL_SLEEP	15	/* seconds */

/*
 * Slave information storage.
 */
typedef struct _net_slave_info {
    int				sl_inuse;
    net_slave_type		sl_id;
    krb5_context		sl_context;
    int				sl_socket;
    struct sockaddr_in		sl_local_addr;	/* local address */
    struct sockaddr_in		sl_remote_addr;	/* remote address */
} net_slave_info;

/*
 * Error messages.
 */
static const char *net_waiterr_msg = "child wait failed - cannot reap children";
static const char *net_def_realm_fmt = "%s: cannot get default realm (%s).\n";
static const char *net_no_mem_fmt = "%s: cannot get memory.\n";
static const char *net_parse_srv_fmt = "%s: cannot parse server name %s (%s).\n";
static const char *net_no_hostname_fmt = "%s: cannot get our host name (%s).\n";
static const char *net_no_hostent_fmt = "%s: cannot get our host entry (%s).\n";
static const char *net_no_servent_fmt = "%s: cannot get service entry for %s (%s).\n";
static const char *net_sockerr_fmt = "%s: cannot open network socket (%s).\n";
static const char *net_binderr_fmt = "%s: cannot bind to network address (%s).\n";

static const char *net_select_fmt = "select failed";
static const char *net_cl_disp_fmt = "client dispatch failed";
static const char *net_not_ready_fmt = "select error - no socket to read";
static const char *net_dispatch_msg = "network dispatch";

static int net_debug_level = 0;

static char		*net_service_name = (char *) NULL;
static int		net_service_princ_init = 0;
static krb5_principal	net_service_principal = (krb5_principal) NULL;
static int		net_server_addr_init = 0;
static struct sockaddr_in	net_server_addr;
static int		net_listen_socket = -1;
static int		net_slaves_active = 0;
static int		net_max_slaves = 0;
static net_slave_info	*net_slave_table = (net_slave_info *) NULL;

static jmp_buf	shutdown_jmp;

extern char *programname;

/*
 * net_find_free_entry()	- Find a free entry in the slave table.
 */
static net_slave_info *
net_find_free_entry()
{
    int i, found;

    /* Find a table entry */
    while (1) {
	found = 0;
	for (i=0; i<net_max_slaves; i++) {
	    if (!net_slave_table[i].sl_inuse) {
		net_slave_table[i].sl_inuse = 1;
		found = 1;
		break;
	    }
	}
	if (found)
	    break;
	sleep(NET_SLAVE_FULL_SLEEP);
    }
    return(&net_slave_table[i]);
}

/*
 * net_find_slave()	- Find a slave entry by its identity.
 */
static net_slave_info *
net_find_slave(id)
    net_slave_type	id;
{
    int i, found;

    for (i=0; i<net_max_slaves; i++) {
	if (net_slave_table[i].sl_inuse &&
	    (net_slave_table[i].sl_id == id)) {
	    found = 1;
	    break;
	}
    }
    if (found)
	return(&net_slave_table[i]);
    else
	return((net_slave_info *) NULL);
}

/*
 * net_free_slave_entry()	- Mark an entry as free.
 */
static void
net_free_slave_entry(entp)
    net_slave_info *entp;
{
    entp->sl_inuse = 0;
}

/*
 * net_shutdown()	- Destroy all slaves on signal reception
 */
static krb5_sigtype
net_shutdown()
{
    int i;

    /* Loop through all slaves */
    for (i=0; i<net_max_slaves; i++) {
	if (net_slave_table[i].sl_inuse){
#ifdef	DEBUG
	    /* If not us (see net_dispatch_client) */
	    if (net_slave_table[i].sl_id != (net_slave_type) getpid()) {
#endif	/* DEBUG */
#if	USE_PTHREADS
		pthread_cancel(*net_slave_table[i].sl_id);
#else	/* USE_PTHREADS */
	    	kill(net_slave_table[i].sl_id, SIGKILL);
#endif	/* USE_PTHREADS */
#ifdef	DEBUG
	    }
#endif	/* DEBUG */
	}
    }
    sleep(5);		/* to allow children to die and be reaped */
    longjmp(shutdown_jmp, 1);
    /* NOTREACHED */
}

#if	!USE_PTHREADS
/*
 * net_reaper()	- Child process termination handler.
 */
static krb5_sigtype
net_reaper()
{
#ifdef	WAIT_USES_INT
    int 		child_exit;
#else	/* WAIT_USES_INT */
    union wait		child_exit;
#endif	/* WAIT_USES_INT */
    pid_t		deadmeat;
    net_slave_info	*slent;

    /* Reap everybody we can */
    while (
	   (
#ifdef	HAVE_WAITPID
	    deadmeat = waitpid((pid_t) -1, &child_exit, WNOHANG)
#else	/* HAVE_WAITPID */
	    deadmeat = wait3(&child_exit, WNOHANG, (struct rusage *) NULL)
#endif	/* HAVE_WAITPID */
	    ) > 0) {
	DPRINT(DEBUG_SPROC, net_debug_level,
	       ("| process %d finished with %d\n", deadmeat, child_exit));
	slent = net_find_slave(deadmeat);
	if (slent) {
	    net_free_slave_entry(slent);
	}
	else {
	    DPRINT(DEBUG_SPROC, net_debug_level,
		   ("| cannot find slave entry for %d\n", deadmeat));
	}
    }
    if ((deadmeat == -1) && (errno != ECHILD))
	com_err(programname, errno, net_waiterr_msg);
}
#endif	/* USE_PTHREADS */

#if	USE_PTHREADS
/*
 * net_slave_proto()	- pthread main routine.
 */
static krb5_error_code
net_slave_proto(stent)
    net_slave_info	*stent;
{
    krb5_error_code	kret;

    DPRINT(DEBUG_CALLS, net_debug_level,
	   ("* net_slave_proto()\n"));
    DPRINT(DEBUG_SPROC, net_debug_level,
	   ("| thread %d starting\n", stent->sl_id));
    kret = proto_serv(stent->sl_context,
		      (krb5_int32) stent->sl_id,
		      stent->sl_socket,
		      &stent->sl_local_addr,
		      &stent->sl_remote_addr);
    DPRINT(DEBUG_SPROC, net_debug_level,
	   ("| thread %d finished with %d\n", stent->sl_id, kret));
    DPRINT(DEBUG_CALLS, net_debug_level,
	   ("* net_slave_proto() = %d\n", kret));
    net_free_slave_entry(stent);
    return(kret);
}
#endif	/* USE_PTHREADS */

/*
 * net_dispatch_client()	- Handle client dispatch.
 */
static krb5_error_code
net_dispatch_client(kcontext, listen_sock, conn_sock, client_addr)
    krb5_context	kcontext;
    int			listen_sock;
    int			conn_sock;
    struct sockaddr_in	*client_addr;
{
    krb5_error_code	kret;
    net_slave_info	*slent;

    DPRINT(DEBUG_CALLS, net_debug_level,
	   ("* net_dispatch_client(listen=%d)\n", listen_sock));
    kret = 0;

    /* Find a free entry */
    slent = net_find_free_entry();

    /* Initialize the slave entry */
    slent->sl_context = kcontext;
    slent->sl_socket = conn_sock;
    memcpy((char *) &slent->sl_remote_addr,
	   (char *) client_addr,
	   sizeof(struct sockaddr_in));
    memcpy((char *) &slent->sl_local_addr,
	   (char *) &net_server_addr,
	   sizeof(struct sockaddr_in));

#ifdef	DEBUG
    if (net_debug_level < DEBUG_REQUESTS) {
#endif	/* DEBUG */
	/* Do a real slave creation */
#if	USE_PTHREADS
	if (!slent->sl_id)
	    slent->sl_id = (pthread_t *) malloc(sizeof(pthread_t));
	if (slent->sl_id == (pthread_t *) NULL) {
	    kret = ENOMEM;
	    goto done;
	}
	if (kret = pthread_create(slent->sl_id,
				  pthread_attr_default,
				  (pthread_startroutine_t) net_slave_proto,
				  (pthread_addr_t) slent)) {
	    kret = errno;
	    goto done;
	}
	if (pthread_detach(slent->sl_id)) {
	    DPRINT(DEBUG_SPROC, net_debug_level,
		   ("| (%d) child thread %d detach failed (%d)\n",
		    getpid(), slent->sl_id, errno));
	}
	DPRINT(DEBUG_SPROC, net_debug_level,
	       ("| (%d) created child thread %d\n",
		getpid(), slent->sl_id));
#else	/* USE_PTHREADS */
	slent->sl_id = fork();
	if (slent->sl_id < 0) {
	    kret = errno;
	    slent->sl_inuse = 0;
	    goto done;
	}

	if (slent->sl_id > 0) {
	    /* parent */
	    DPRINT(DEBUG_SPROC, net_debug_level,
		   ("| (%d) created child process %d\n",
		    getpid(), slent->sl_id));
	    kret = 0;
	    goto done;
	}
	else {
	    /* child */
	    signal(SIGINT, SIG_IGN);	/* Ignore SIGINT */
	    signal(SIGTERM, SIG_IGN);	/* Ignore SIGTERM */
	    signal(SIGHUP, SIG_IGN);	/* Ignore SIGHUP */
	    signal(SIGQUIT, SIG_IGN);	/* Ignore SIGQUIT */
	    signal(SIGPIPE, SIG_IGN);	/* Ignore SIGPIPE */
	    signal(SIGCHLD, SIG_DFL);	/* restore SIGCHLD handling */
	    close(listen_sock);
	    DPRINT(DEBUG_SPROC, net_debug_level,
		   ("| process %d starting\n", getpid()));
	    kret = proto_serv(slent->sl_context,
			      (krb5_int32) slent->sl_id,
			      slent->sl_socket,
			      &slent->sl_local_addr,
			      &slent->sl_remote_addr);
	    DPRINT(DEBUG_SPROC, net_debug_level,
		   ("| process %d exiting with %d\n", getpid(), kret));
	    exit(kret);
	}
#endif	/* USE_PTHREADS */
#ifdef	DEBUG
    }
    else {
	net_slave_info *sl1;
	DPRINT(DEBUG_SPROC, net_debug_level,
	       ("| (%d) not doing child creation\n", getpid()));
	slent->sl_id = (net_slave_type) getpid();
	kret = proto_serv(slent->sl_context,
			  (krb5_int32) slent->sl_id,
			  slent->sl_socket,
			  &slent->sl_local_addr,
			  &slent->sl_remote_addr);
	sl1 = net_find_slave(slent->sl_id);
	if (!sl1)
	    net_free_slave_entry(sl1);
	DPRINT(DEBUG_SPROC, net_debug_level,
	       ("| (%d) returned with %d\n", getpid(), kret));
    }
#endif	/* DEBUG */
 done:
    DPRINT(DEBUG_CALLS, net_debug_level,
	   ("X net_dispatch_client() = %d\n", kret));
    return(kret);
}

/*
 * net_init()	- Initialize network context.
 */
krb5_error_code
net_init(kcontext, debug_level)
    krb5_context	kcontext;
    int			debug_level;
{
    krb5_error_code	kret;
    char		*local_realm;
    char		our_host_name[MAXHOSTNAMELEN];
    struct hostent	*our_hostent;
    struct servent	*our_servent;
    int			bind_tries;
    int			bind_sleep;

    net_debug_level = debug_level;
    DPRINT(DEBUG_CALLS, net_debug_level, ("* net_init()\n"));

    /*
     * Get our realm.
     */
    if (kret = krb5_get_default_realm(kcontext, &local_realm)) {
	fprintf(stderr, net_def_realm_fmt, programname, error_message(kret));
	goto done;
    }

    /* Allocate the slave table */
    net_slave_table = (net_slave_info *) malloc(MAX_SLAVES *
						sizeof(net_slave_info));
    /* Make our service name */
    net_service_name = (char *) malloc(strlen(local_realm) +
				       strlen(KRB5_ADM_SERVICE_NAME) + 2);
    if ((net_service_name == (char *) NULL) ||
	(net_slave_table == (net_slave_info *) NULL)) {
	kret = ENOMEM;
	krb5_xfree(local_realm);
	fprintf(stderr, net_no_mem_fmt, programname);
	goto done;
    }
    (void) sprintf(net_service_name, "%s%s%s",
		   KRB5_ADM_SERVICE_NAME, "/", local_realm);
    krb5_xfree(local_realm);
    memset((char *) net_slave_table, 0, MAX_SLAVES * sizeof(net_slave_info));
    net_max_slaves = MAX_SLAVES;
    DPRINT(DEBUG_HOST, net_debug_level,
	   ("- name of service is %s\n", net_service_name));

    /* Now formulate the principal name */
    if (kret = krb5_parse_name(kcontext,
			       net_service_name,
			       &net_service_principal)) {
	fprintf(stderr, net_parse_srv_fmt, programname, net_service_name,
		error_message(kret));
	goto done;
    }
    net_service_princ_init = 1;

    /* Now get our host name/entry */
    if (gethostname(our_host_name, sizeof(our_host_name))) {
	kret = errno;
	fprintf(stderr, net_no_hostname_fmt, programname, error_message(kret));
	goto done;
    }
    if (!(our_hostent = gethostbyname(our_host_name))) {
	kret = errno;
	fprintf(stderr, net_no_hostent_fmt, programname, error_message(kret));
	goto done;
    }
    DPRINT(DEBUG_HOST, net_debug_level,
	   ("- name of host is %s\n", our_hostent->h_name));

    /* Now initialize our network address */
    net_server_addr.sin_family = AF_INET;
    memcpy((char *) &net_server_addr.sin_addr,
	   (char *) our_hostent->h_addr,
	   sizeof(net_server_addr.sin_addr));
    DPRINT(DEBUG_HOST, net_debug_level,
	   ("- address of host is %x\n",
	    ntohl(net_server_addr.sin_addr.s_addr)));

    /* Get the service entry */
    if (!(our_servent = getservbyname(KRB5_ADM_SERVICE_NAME, "tcp"))) {
	kret = errno;
	fprintf(stderr, net_no_servent_fmt, programname,
		KRB5_ADM_SERVICE_NAME, error_message(kret));
	goto done;
    }
    net_server_addr.sin_port = our_servent->s_port;
    net_server_addr_init = 1;
    DPRINT(DEBUG_HOST, net_debug_level,
	   ("- service name (%s) is on port %d\n", our_servent->s_name,
	    our_servent->s_port));

    /* Now open the listen socket */
    net_listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (net_listen_socket < 0) {
	kret = errno;
	fprintf(stderr, net_sockerr_fmt, programname, error_message(kret));
	goto done;
    }

    /* Bind socket */
    bind_sleep = 1;
    bind_tries = 0;
    do {
	if (bind(net_listen_socket,
		 &net_server_addr,
		 sizeof(net_server_addr)) < 0) {
	    kret = errno;
	    if (errno != EADDRINUSE) {
		fprintf(stderr, net_binderr_fmt, programname,
			error_message(kret));
		goto done;
	    }
	    else {
		bind_tries++;
		DPRINT(DEBUG_HOST, net_debug_level,
		       ("- bind failed sleeping for %d seconds\n",
			bind_sleep));
		sleep(bind_sleep);
		bind_sleep = bind_sleep << 1;
	    }
	}
	else {
	    DPRINT(DEBUG_HOST, net_debug_level,
		   ("- bound socket %d on port\n", net_listen_socket));
	    break;
	}
    } while (bind_tries < MAX_BIND_TRIES);

 done:
    DPRINT(DEBUG_CALLS, net_debug_level, ("X net_init() = %d\n", kret));
    return(kret);
}

/*
 * net_finish()	- Finish network context.
 */
void
net_finish(kcontext, debug_level)
    krb5_context	kcontext;
    int			debug_level;
{
    DPRINT(DEBUG_CALLS, net_debug_level, ("* net_finish()\n"));
    if (net_max_slaves)
	free(net_slave_table);
    if (net_listen_socket >= 0)
	close(net_listen_socket);
    if (net_service_princ_init)
	krb5_free_principal(kcontext, net_service_principal);
    if (net_service_name)
	free(net_service_name);
    DPRINT(DEBUG_CALLS, net_debug_level, ("X net_finish()\n"));
}

/*
 * net_dispatch()	- Listen and dispatch request.
 *
 * Loop forever selecting on the listen socket.  When an incoming connection
 * comes in, dispatch to net_client_connect().
 */
krb5_error_code
net_dispatch(kcontext)
    krb5_context	kcontext;
{
    krb5_error_code	kret;
    fd_set		mask, readfds;
    int			nready;

    DPRINT(DEBUG_CALLS, net_debug_level, ("* net_dispatch()\n"));

    kret = 0;

    /* Set up the fdset mask */
    FD_ZERO(&mask);
    FD_SET(net_listen_socket, &mask);

    /*
     * SIGTERM (or SIGINT, if debug) shuts us down.
     */
    signal(SIGTERM, net_shutdown);
#ifdef	DEBUG
    signal(SIGINT, net_shutdown);
#endif	/* DEBUG */

#if	!USE_PTHREADS
    /*
     * SIGCHILD indicates end of child process life.
     */
    signal(SIGCHLD, net_reaper);
#endif	/* !USE_PTHREADS */

    /* Receive connections on the socket */
    DLOG(DEBUG_OPERATION, net_debug_level, "listening on socket");
    if (setjmp(shutdown_jmp) == 0) {
	if (listen(net_listen_socket, SOMAXCONN) < 0)
	    kret = errno;
    }
    else
	kret = EINTR;
    DLOG(DEBUG_OPERATION, net_debug_level, "listen done");

    while (kret == 0) {
	/*
	 * Prepare to catch signals.
	 */
	if (setjmp(shutdown_jmp) == 0) {
	    readfds = mask;
	    DLOG(DEBUG_OPERATION, net_debug_level, "doing select");
	    if ((nready = select(net_listen_socket+1,
				 &readfds,
				 (fd_set *) NULL,
				 (fd_set *) NULL,
				 (struct timeval *) NULL)) == 0) {
		DLOG(DEBUG_OPERATION, net_debug_level, "nobody ready");
		continue;	/* Nobody ready */
	    }

	    if ((nready < 0) && (errno != EINTR)) {
		com_err(net_dispatch_msg, errno, net_select_fmt);
		continue;
	    }

	    if (FD_ISSET(net_listen_socket, &readfds)) {
		struct sockaddr_in	client_addr;
		int			addrlen;
		int			conn_sock;

		addrlen = sizeof(client_addr);
		DLOG(DEBUG_OPERATION, net_debug_level,
		     "accept connection");
		while (((conn_sock = accept(net_listen_socket,
					    (struct sockaddr *) &client_addr,
					    &addrlen)) < 0) &&
		       (errno == EINTR));

		if (conn_sock < 0)  {
		    kret = errno;
		    break;
		}
		DLOG(DEBUG_OPERATION, net_debug_level,
		     "accepted connection");
		kret = net_dispatch_client(kcontext,
					   net_listen_socket,
					   conn_sock,
					   &client_addr);
		if (kret) {
		    com_err(net_dispatch_msg, kret, net_cl_disp_fmt);
		    continue;
		}
		DLOG(DEBUG_OPERATION, net_debug_level, "dispatch done");
	    }
	    else {
		com_err(net_dispatch_msg, 0, net_not_ready_fmt);
		kret = EIO;
	    }
	}
	else {
	    DLOG(DEBUG_OPERATION, net_debug_level,
		 "dispatch interrupted by SIGTERM");
	    kret = 0;
	    break;
	}
    }

    DPRINT(DEBUG_CALLS, net_debug_level, ("X net_dispatch() = %d\n", kret));
    return(kret);
}

/*
 * Return our service principal.
 */
krb5_principal
net_server_princ()
{
    if (net_service_princ_init)
	return(net_service_principal);
    else
	return((krb5_principal) NULL);
}
