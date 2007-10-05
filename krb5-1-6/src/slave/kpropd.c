/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * slave/kpropd.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * XXX We need to modify the protocol so that an acknowledge is set
 * after each block, instead after the entire series is sent over.
 * The reason for this is so that error packets can get interpreted
 * right away.  If you don't do this, the sender may never get the
 * error packet, because it will die an EPIPE trying to complete the
 * write...
 */


#include <stdio.h>
#include <ctype.h>
#include <sys/file.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <netdb.h>
#include <syslog.h>

#include "k5-int.h"
#include "com_err.h"
#include <errno.h>

#include "kprop.h"

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE unsigned int
#endif
#ifndef GETPEERNAME_ARG3_TYPE
#define GETPEERNAME_ARG3_TYPE unsigned int
#endif

#if defined(NEED_DAEMON_PROTO)
extern int daemon(int, int);
#endif

#define SYSLOG_CLASS LOG_DAEMON

static char *kprop_version = KPROP_PROT_VERSION;

char	*progname;
int     debug = 0;
char	*srvtab = 0;
int	standalone = 0;

krb5_principal	server;		/* This is our server principal name */
krb5_principal	client;		/* This is who we're talking to */
krb5_context kpropd_context;
krb5_auth_context auth_context;
char	*realm = NULL;		/* Our realm */
char	*file = KPROPD_DEFAULT_FILE;
char	*temp_file_name;
char	*kdb5_util = KPROPD_DEFAULT_KDB5_UTIL;
char	*kerb_database = NULL;
char	*acl_file_name = KPROPD_ACL_FILE;

krb5_address	sender_addr;
krb5_address	receiver_addr;
short 		port = 0;

void	PRS
	(char**);
void	do_standalone
	(void);
void	doit
	(int);
void	kerberos_authenticate
	(krb5_context,
		   int,
		   krb5_principal *,
		   krb5_enctype *,
		   struct sockaddr_in);
krb5_boolean authorized_principal
	(krb5_context,
    		   krb5_principal,
		   krb5_enctype);
void	recv_database
	(krb5_context,
		   int,
		   int,
		   krb5_data *);
void	load_database
	(krb5_context,
    		   char *,
    		   char *);
void	send_error
	(krb5_context,
    		   int,
		   krb5_error_code,
    		   char	*);
void	recv_error
	(krb5_context,
    		   krb5_data *);

static void usage()
{
	fprintf(stderr,
		"\nUsage: %s [-r realm] [-s srvtab] [-dS] [-f slave_file]\n",
		progname);
	fprintf(stderr, "\t[-F kerberos_db_file ] [-p kdb5_util_pathname]\n");
	fprintf(stderr, "\t[-P port] [-a acl_file]\n");
	exit(1);
}

int
main(argc, argv)
	int	argc;
	char	**argv;
{
	PRS(argv);

	if (standalone)
		do_standalone();
	else
		doit(0);
	exit(0);
}

void do_standalone()
{
	struct	sockaddr_in	my_sin, frominet;
	struct servent *sp;
	int	finet, s;
	GETPEERNAME_ARG3_TYPE fromlen;
	int	ret;
	
	finet = socket(AF_INET, SOCK_STREAM, 0);
	if (finet < 0) {
		com_err(progname, errno, "while obtaining socket");
		exit(1);
	}
	memset((char *) &my_sin,0, sizeof(my_sin));
	if(!port) {
		sp = getservbyname(KPROP_SERVICE, "tcp");
		if (sp == NULL) {
			com_err(progname, 0, "%s/tcp: unknown service", KPROP_SERVICE);
			my_sin.sin_port = htons(KPROP_PORT);
		}
		else my_sin.sin_port = sp->s_port;
	} else {
		my_sin.sin_port = port;
	}
	my_sin.sin_family = AF_INET;
	if ((ret = bind(finet, (struct sockaddr *) &my_sin, sizeof(my_sin))) < 0) {
	    if (debug) {
		int on = 1;
		fprintf(stderr,
			"%s: attempting to rebind socket with SO_REUSEADDR\n",
			progname);
		if (setsockopt(finet, SOL_SOCKET, SO_REUSEADDR,
			       (char *)&on, sizeof(on)) < 0)
		    com_err(progname, errno, "in setsockopt(SO_REUSEADDR)");
		ret = bind(finet, (struct sockaddr *) &my_sin, sizeof(my_sin));
	    }
	    if (ret < 0) {
		perror("bind");
		com_err(progname, errno, "while binding listener socket");
		exit(1);
	    }
	}
	if (!debug)
		daemon(1, 0);	    
#ifdef PID_FILE
	if ((pidfile = fopen(PID_FILE, "w")) != NULL) {
		fprintf(pidfile, "%d\n", getpid());
		fclose(pidfile);
	} else
		com_err(progname, errno,
			"while opening pid file %s for writing", PID_FILE);
#endif
	if (listen(finet, 5) < 0) {
		com_err(progname, errno, "in listen call");
		exit(1);
	}
	while (1) {
		int child_pid;
	    
		memset((char *)&frominet, 0, sizeof(frominet));
		fromlen = sizeof(frominet);
		s = accept(finet, (struct sockaddr *) &frominet, &fromlen);

		if (s < 0) {
			if (errno != EINTR)
				com_err(progname, errno,
					"from accept system call");
			continue;
		}
		if (debug)
			child_pid = 0;
		else
			child_pid = fork();
		switch (child_pid) {
		case -1:
			com_err(progname, errno, "while forking");
			exit(1);
		case 0:
			(void) close(finet);

			doit(s);
			close(s);
			_exit(0);
		default:
			wait(0);
			close(s);
			
		}
	}
}

void doit(fd)
	int	fd;
{
	struct sockaddr_in from;
	int on = 1;
	GETPEERNAME_ARG3_TYPE fromlen;
	struct hostent	*hp;
	krb5_error_code	retval;
	krb5_data confmsg;
	int lock_fd;
	mode_t omask;
	krb5_enctype etype;
	int database_fd;

	fromlen = sizeof (from);
	if (getpeername(fd, (struct sockaddr *) &from, &fromlen) < 0) {
		fprintf(stderr, "%s: ", progname);
		perror("getpeername");
		exit(1);
	}
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (caddr_t) &on,
		       sizeof (on)) < 0) {
		com_err(progname, errno,
			"while attempting setsockopt (SO_KEEPALIVE)");
	}

	if (!(hp = gethostbyaddr((char *) &(from.sin_addr.s_addr), fromlen,
				 AF_INET))) {
		syslog(LOG_INFO, "Connection from %s",
		       inet_ntoa(from.sin_addr));
		if (debug)
			printf("Connection from %s\n",
			       inet_ntoa(from.sin_addr));
	} else {
		syslog(LOG_INFO, "Connection from %s", hp->h_name);
		if (debug)
			printf("Connection from %s\n", hp->h_name);
	}

	/*
	 * Now do the authentication
	 */
	kerberos_authenticate(kpropd_context, fd, &client, &etype, from);

	if (!authorized_principal(kpropd_context, client, etype)) {
		char	*name;

		retval = krb5_unparse_name(kpropd_context, client, &name);
		if (retval) {
			com_err(progname, retval,
				"While unparsing client name");
			exit(1);
		}
		syslog(LOG_WARNING,
		       "Rejected connection from unauthorized principal %s",
		       name);
		free(name);
		exit(1);
	}
	omask = umask(077);
	lock_fd = open(temp_file_name, O_RDWR|O_CREAT, 0600);
	(void) umask(omask);
	retval = krb5_lock_file(kpropd_context, lock_fd, 
				KRB5_LOCKMODE_EXCLUSIVE|KRB5_LOCKMODE_DONTBLOCK);
	if (retval) {
	    com_err(progname, retval, "while trying to lock '%s'",
		    temp_file_name);
	    exit(1);
	}
	if ((database_fd = open(temp_file_name,
				O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
		com_err(progname, errno,
			"while opening database file, '%s'",
			temp_file_name);
		exit(1);
	}
	recv_database(kpropd_context, fd, database_fd, &confmsg);
	if (rename(temp_file_name, file)) {
		com_err(progname, errno, "While renaming %s to %s",
			temp_file_name, file);
		exit(1);
	}
	retval = krb5_lock_file(kpropd_context, lock_fd, KRB5_LOCKMODE_SHARED);
	if (retval) {
	    com_err(progname, retval, "while downgrading lock on '%s'",
		    temp_file_name);
	    exit(1);
	}
	load_database(kpropd_context, kdb5_util, file);
	retval = krb5_lock_file(kpropd_context, lock_fd, KRB5_LOCKMODE_UNLOCK);
	if (retval) {
	    com_err(progname, retval, "while unlocking '%s'", temp_file_name);
	    exit(1);
	}
	(void)close(lock_fd);

	/*
	 * Send the acknowledgement message generated in
	 * recv_database, then close the socket.
	 */
	retval = krb5_write_message(kpropd_context, (void *) &fd, &confmsg);
	if (retval) { 
		krb5_free_data_contents(kpropd_context, &confmsg);
		com_err(progname, retval,
			"while sending # of received bytes");
		exit(1);
	}
	krb5_free_data_contents(kpropd_context, &confmsg);
	if (close(fd) < 0) {
		com_err(progname, errno,
			"while trying to close database file");
		exit(1);
	}
	
	exit(0);
}

static void
kpropd_com_err_proc(whoami, code, fmt, args)
	const char	*whoami;
	long		code;
	const char	*fmt;
	va_list		args;
{
	char	error_buf[8096];

	error_buf[0] = '\0';
	if (fmt)
		vsprintf(error_buf, fmt, args);
	syslog(LOG_ERR, "%s%s%s%s%s", whoami ? whoami : "", whoami ? ": " : "",
	       code ? error_message(code) : "", code ? " " : "", error_buf);
}

void PRS(argv)
	char	**argv;
{
	register char	*word, ch;
	krb5_error_code	retval;
	static const char	tmp[] = ".temp";
	
	retval = krb5_init_context(&kpropd_context);
	if (retval) {
		com_err(argv[0], retval, "while initializing krb5");
		exit(1);
	}

	progname = *argv++;
	while ((word = *argv++)) {
		if (*word == '-') {
			word++;
			while (word && (ch = *word++)) {
				switch(ch){
				case 'f':
					if (*word)
						file = word;
					else
						file = *argv++;
					if (!file)
						usage();
					word = 0;
					break;
				case 'F':
					if (*word)
						kerb_database = word;
					else
						kerb_database = *argv++;
					if (!kerb_database)
						usage();
					word = 0;
					break;
				case 'p':
					if (*word)
						kdb5_util = word;
					else
						kdb5_util = *argv++;
					if (!kdb5_util)
						usage();
					word = 0;
					break;
				case 'P':
					if (*word)
						port = htons(atoi(word));
					else
						port = htons(atoi(*argv++));
					if (!port)
						usage();
					word = 0;
					break;
				case 'r':
					if (*word)
						realm = word;
					else
						realm = *argv++;
					if (!realm)
						usage();
					word = 0;
					break;
				case 's':
					if (*word)
						srvtab = word;
					else
						srvtab = *argv++;
					if (!srvtab)
						usage();
					word = 0;
					break;
				case 'd':
					debug++;
					break;
				case 'S':
					standalone++;
					break;
				case 'a':
					if (*word)
					     acl_file_name = word;
					else
					     acl_file_name = *argv++;
					if (!acl_file_name)
					     usage();
					word = 0;
					break;
				default:
					usage();
				}
				
			}
		} else
			/* We don't take any arguments, only options */
			usage();
	}
	/*
	 * If not in debug mode, switch com_err reporting to syslog
	 */
	if (! debug) {
	    openlog("kpropd", LOG_PID | LOG_ODELAY, SYSLOG_CLASS);
	    set_com_err_hook(kpropd_com_err_proc);
	}
	/*
	 * Get my hostname, so we can construct my service name
	 */
	retval = krb5_sname_to_principal(kpropd_context,
					 NULL, KPROP_SERVICE_NAME,
					 KRB5_NT_SRV_HST, &server);
	if (retval) {
		com_err(progname, retval,
			"While trying to construct my service name");
		exit(1);
	}
	if (realm) {
	    retval = krb5_set_principal_realm(kpropd_context, server, realm);
	    if (retval) {
	        com_err(progname, errno, 
			"while constructing my service realm");
		exit(1);
	    }
	}
	/*
	 * Construct the name of the temporary file.
	 */
	if ((temp_file_name = (char *) malloc(strlen(file) +
					       strlen(tmp) + 1)) == NULL) {
		com_err(progname, ENOMEM,
			"while allocating filename for temp file");
		exit(1);
	}
	strcpy(temp_file_name, file);
	strcat(temp_file_name, tmp);
}

/*
 * Figure out who's calling on the other end of the connection....
 */
void
kerberos_authenticate(context, fd, clientp, etype, my_sin)
    krb5_context 	  context;
    int		 	  fd;
    krb5_principal	* clientp;
    krb5_enctype	* etype;
    struct sockaddr_in	  my_sin;
{
    krb5_error_code	  retval;
    krb5_ticket		* ticket;
    struct sockaddr_in	  r_sin;
    GETSOCKNAME_ARG3_TYPE sin_length;
    krb5_keytab		  keytab = NULL;

    /*
     * Set recv_addr and send_addr
     */
    sender_addr.addrtype = ADDRTYPE_INET;
    sender_addr.length = sizeof(my_sin.sin_addr);
    sender_addr.contents = (krb5_octet *) malloc(sizeof(my_sin.sin_addr));
    memcpy((char *) sender_addr.contents, (char *) &my_sin.sin_addr,
           sizeof(my_sin.sin_addr));

    sin_length = sizeof(r_sin);
    if (getsockname(fd, (struct sockaddr *) &r_sin, &sin_length)) {
	com_err(progname, errno, "while getting local socket address");
	exit(1);
    }

    receiver_addr.addrtype = ADDRTYPE_INET;
    receiver_addr.length = sizeof(r_sin.sin_addr);
    receiver_addr.contents = (krb5_octet *) malloc(sizeof(r_sin.sin_addr));
    memcpy((char *) receiver_addr.contents, (char *) &r_sin.sin_addr,
           sizeof(r_sin.sin_addr));

    if (debug) {
	char *name;

	retval = krb5_unparse_name(context, server, &name);
	if (retval) {
	    com_err(progname, retval, "While unparsing client name");
	    exit(1);
	}
	printf("krb5_recvauth(%d, %s, %s, ...)\n", fd, kprop_version, name);
	free(name);
    }

    retval = krb5_auth_con_init(context, &auth_context);
    if (retval) {
	syslog(LOG_ERR, "Error in krb5_auth_con_ini: %s",
	       error_message(retval));
    	exit(1);
    }

    retval = krb5_auth_con_setflags(context, auth_context, 
				    KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    if (retval) {
	syslog(LOG_ERR, "Error in krb5_auth_con_setflags: %s",
	       error_message(retval));
	exit(1);
    }

    retval = krb5_auth_con_setaddrs(context, auth_context, &receiver_addr,
				    &sender_addr);
    if (retval) {
	syslog(LOG_ERR, "Error in krb5_auth_con_setaddrs: %s",
	       error_message(retval));
	exit(1);
    }

    if (srvtab) {
        retval = krb5_kt_resolve(context, srvtab, &keytab);
	if (retval) {
	  syslog(LOG_ERR, "Error in krb5_kt_resolve: %s", error_message(retval));
	  exit(1);
	}
    }

    retval = krb5_recvauth(context, &auth_context, (void *) &fd,
			   kprop_version, server, 0, keytab, &ticket);
    if (retval) {
	syslog(LOG_ERR, "Error in krb5_recvauth: %s", error_message(retval));
	exit(1);
    }

    retval = krb5_copy_principal(context, ticket->enc_part2->client, clientp);
    if (retval) {
	syslog(LOG_ERR, "Error in krb5_copy_prinicpal: %s", 
	       error_message(retval));
	exit(1);
    }

    *etype = ticket->enc_part.enctype;

    if (debug) {
	char * name;
	char etypebuf[100];

	retval = krb5_unparse_name(context, *clientp, &name);
	if (retval) {
	    com_err(progname, retval, "While unparsing client name");
	    exit(1);
	}

	retval = krb5_enctype_to_string(*etype, etypebuf, sizeof(etypebuf));
	if (retval) {
	    com_err(progname, retval, "While unparsing ticket etype");
	    exit(1);
	}

	printf("authenticated client: %s (etype == %s)\n", name, etypebuf);
	free(name);
    }

    krb5_free_ticket(context, ticket);
}

krb5_boolean
authorized_principal(context, p, auth_etype)
    krb5_context context;
    krb5_principal p;
    krb5_enctype auth_etype;
{
    char		*name, *ptr;
    char		buf[1024];
    krb5_error_code	retval;
    FILE		*acl_file;
    int			end;
    krb5_enctype	acl_etype;
    
    retval = krb5_unparse_name(context, p, &name);
    if (retval)
	return FALSE;

    acl_file = fopen(acl_file_name, "r");
    if (!acl_file)
	return FALSE;

    while (!feof(acl_file)) {
	if (!fgets(buf, sizeof(buf), acl_file))
	    break;
	end = strlen(buf) - 1;
	if (buf[end] == '\n')
	    buf[end] = '\0';
	if (!strncmp(name, buf, strlen(name))) {
	    ptr = buf+strlen(name);

	    /* if the next character is not whitespace or nul, then
	       the match is only partial.  continue on to new lines. */
	    if (*ptr && !isspace((int) *ptr))
		continue;

	    /* otherwise, skip trailing whitespace */
	    for (; *ptr && isspace((int) *ptr); ptr++) ;

	    /* now, look for an etype string. if there isn't one,
	       return true.  if there is an invalid string, continue.
	       If there is a valid string, return true only if it
	       matches the etype passed in, otherwise continue */

	    if ((*ptr) &&
		((retval = krb5_string_to_enctype(ptr, &acl_etype)) ||
		 (acl_etype != auth_etype)))
		continue;

	    free(name);
	    fclose(acl_file);
	    return TRUE;
	}
    }
    free(name);
    fclose(acl_file);
    return FALSE;
}

void
recv_database(context, fd, database_fd, confmsg)
    krb5_context context;
    int	fd;
    int	database_fd;
    krb5_data *confmsg;
{
	krb5_ui_4	database_size; /* This must be 4 bytes */
	int	received_size, n;
	char		buf[1024];
	krb5_data	inbuf, outbuf;
	krb5_error_code	retval;

	/*
	 * Receive and decode size from client
	 */
	retval = krb5_read_message(context, (void *) &fd, &inbuf);
	if (retval) {
		send_error(context, fd, retval, "while reading database size");
		com_err(progname, retval,
			"while reading size of database from client");
		exit(1);
	}
	if (krb5_is_krb_error(&inbuf))
		recv_error(context, &inbuf);
	retval = krb5_rd_safe(context,auth_context,&inbuf,&outbuf,NULL);
	if (retval) {
		send_error(context, fd, retval, 
			   "while decoding database size");
		krb5_free_data_contents(context, &inbuf);
		com_err(progname, retval,
			"while decoding database size from client");
		exit(1);
	}
	memcpy((char *) &database_size, outbuf.data, sizeof(database_size));
	krb5_free_data_contents(context, &inbuf);
	krb5_free_data_contents(context, &outbuf);
	database_size = ntohl(database_size);

	/*
	 * Initialize the initial vector.
	 */
	retval = krb5_auth_con_initivector(context, auth_context);
	if (retval) {
	  send_error(context, fd, retval, 
		     "failed while initializing i_vector");
	  com_err(progname, retval, "while initializing i_vector");
	  exit(1);
	}

	/*
	 * Now start receiving the database from the net
	 */
	received_size = 0;
	while (received_size < database_size) {
	        retval = krb5_read_message(context, (void *) &fd, &inbuf);
		if (retval) {
			sprintf(buf,
				"while reading database block starting at offset %d",
				received_size);
			com_err(progname, retval, buf);
			send_error(context, fd, retval, buf);
			exit(1);
		}
		if (krb5_is_krb_error(&inbuf))
			recv_error(context, &inbuf);
		retval = krb5_rd_priv(context, auth_context, &inbuf, 
				      &outbuf, NULL);
		if (retval) {
			sprintf(buf,
				"while decoding database block starting at offset %d",
				received_size);
			com_err(progname, retval, buf);
			send_error(context, fd, retval, buf);
			krb5_free_data_contents(context, &inbuf);
			exit(1);
		}
		n = write(database_fd, outbuf.data, outbuf.length);
		krb5_free_data_contents(context, &inbuf);
		krb5_free_data_contents(context, &outbuf);
		if (n < 0) {
			sprintf(buf,
				"while writing database block starting at offset %d",
				received_size);
			send_error(context, fd, errno, buf);
		} else if (n != outbuf.length) {
			sprintf(buf,
				"incomplete write while writing database block starting at \noffset %d (%d written, %d expected)",
				received_size, n, outbuf.length);
			send_error(context, fd, KRB5KRB_ERR_GENERIC, buf);
		}
		received_size += outbuf.length;
	}
	/*
	 * OK, we've seen the entire file.  Did we get too many bytes?
	 */
	if (received_size > database_size) {
		sprintf(buf,
			"Received %d bytes, expected %d bytes for database file",
			received_size, database_size);
		send_error(context, fd, KRB5KRB_ERR_GENERIC, buf);
	}
	/*
	 * Create message acknowledging number of bytes received, but
	 * don't send it until kdb5_util returns successfully.
	 */
	database_size = htonl(database_size);
	inbuf.data = (char *) &database_size;
	inbuf.length = sizeof(database_size);
	retval = krb5_mk_safe(context,auth_context,&inbuf,confmsg,NULL);
	if (retval) {
		com_err(progname, retval,
			"while encoding # of receieved bytes");
		send_error(context, fd, retval,
			   "while encoding # of received bytes");
		exit(1);
	}
}


void
send_error(context, fd, err_code, err_text)
    krb5_context context;
    int	fd;
    krb5_error_code	err_code;
    char	*err_text;
{
	krb5_error	error;
	const char	*text;
	krb5_data	outbuf;
	char		buf[1024];

	memset((char *)&error, 0, sizeof(error));
	krb5_us_timeofday(context, &error.stime, &error.susec);
	error.server = server;
	error.client = client;
	
	if (err_text)
		text = err_text;
	else
		text = error_message(err_code);
	
	error.error = err_code - ERROR_TABLE_BASE_krb5;
	if (error.error > 127) {
		error.error = KRB_ERR_GENERIC;
		if (err_text) {
			sprintf(buf, "%s %s", error_message(err_code),
				err_text);
			text = buf;
		}
	} 
	error.text.length = strlen(text) + 1;
	error.text.data = malloc(error.text.length);
	if (error.text.data) {
		strcpy(error.text.data, text);
		if (!krb5_mk_error(context, &error, &outbuf)) {
			(void) krb5_write_message(context, (void *)&fd,&outbuf);
			krb5_free_data_contents(context, &outbuf);
		}
		free(error.text.data);
	}
}

void
recv_error(context, inbuf)
    krb5_context context;
    krb5_data	*inbuf;
{
	krb5_error	*error;
	krb5_error_code	retval;

	retval = krb5_rd_error(context, inbuf, &error);
	if (retval) {
		com_err(progname, retval,
			"while decoding error packet from client");
		exit(1);
	}
	if (error->error == KRB_ERR_GENERIC) {
		if (error->text.data)
			fprintf(stderr,
				"Generic remote error: %s\n",
				error->text.data);
	} else if (error->error) {
		com_err(progname, 
			(krb5_error_code) error->error + ERROR_TABLE_BASE_krb5,
			"signalled from server");
		if (error->text.data)
			fprintf(stderr,
				"Error text from client: %s\n",
				error->text.data);
	}
	krb5_free_error(context, error);
	exit(1);
}

void
load_database(context, kdb_util, database_file_name)
    krb5_context context;
    char *kdb_util;
    char *database_file_name;
{
	static char	*edit_av[10];
	int	error_ret, save_stderr = -1;
	int	child_pid;
	int 	count;

	/* <sys/param.h> has been included, so BSD will be defined on
	   BSD systems */
#if BSD > 0 && BSD <= 43
#ifndef WEXITSTATUS
#define	WEXITSTATUS(w) (w).w_retcode
#endif
	union wait	waitb;
#else
	int	waitb;
#endif
	krb5_error_code	retval;

	if (debug)
		printf("calling kdb5_util to load database\n");

	edit_av[0] = kdb_util;
	count = 1;
	if (realm) {
		edit_av[count++] = "-r";	
		edit_av[count++] = realm;	
	}
	edit_av[count++] = "load";
	if (kerb_database) {
		edit_av[count++] = "-d";
		edit_av[count++] = kerb_database;
	}
	edit_av[count++] = database_file_name;
	edit_av[count++] = NULL;

	switch(child_pid = fork()) {
	case -1:
		com_err(progname, errno, "while trying to fork %s",
			kdb_util);
		exit(1);
	case 0:
		if (!debug) {
			save_stderr = dup(2);
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDWR);
			dup(0);
			dup(0);
		}

		execv(kdb_util, edit_av);
		retval = errno;
		if (!debug)
			dup2(save_stderr, 2);
		com_err(progname, retval, "while trying to exec %s",
			kdb_util);
		_exit(1);
		/*NOTREACHED*/
	default:
		if (debug)
		    printf("Child PID is %d\n", child_pid);
		if (wait(&waitb) < 0) {
			com_err(progname, errno, "while waiting for %s",
				kdb_util);
			exit(1);
		}
	}
	
	error_ret = WEXITSTATUS(waitb);
	if (error_ret) {
		com_err(progname, 0, "%s returned a bad exit status (%d)",
			kdb_util, error_ret);
		exit(1);
	}
	return;
}
