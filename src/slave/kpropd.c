/*
 * $Source$
 * $Author$
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
 * permission.  M.I.T. makes no representations about the suitability of
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

#if !defined(lint) && !defined(SABER)
static char rcsid_kpropd_c[] =
"$Id$";
#endif /* !lint && !SABER */

#include <stdio.h>
#include <ctype.h>
#include <sys/file.h>
#include <signal.h>
#include <string.h>
#include <sgtty.h>
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

#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/osconf.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <com_err.h>
#include <errno.h>

#include "kprop.h"

#define SYSLOG_CLASS LOG_DAEMON

static char *kprop_version = KPROP_PROT_VERSION;

char	*progname;
int     debug = 0;
char	*srvtab = 0;
int	standalone;

krb5_principal	server;		/* This is our server principal name */
krb5_principal	client;		/* This is who we're talking to */
krb5_keyblock	*session_key;	/* Here is the session key */
krb5_address	**server_addrs;
krb5_pointer	kerb_keytab = 0; /* Use default */
char	*realm = NULL;		/* Our realm */
char	*file = KPROPD_DEFAULT_FILE;
char	*temp_file_name;
char	*kdb5_edit = KPROPD_DEFAULT_KDB5_EDIT;
char	*kerb_database = KPROPD_DEFAULT_KRB_DB;

int		database_fd;
krb5_int32	my_seq_num;	/* Sequence number */
krb5_int32	his_seq_num;	/* The remote's sequence number */
krb5_address	sender_addr;
krb5_address	receiver_addr;

void	PRS();
void	do_standalone();
void	doit();
void	detach_process();
void	kerberos_authenticate();
krb5_boolean authorized_principal();
void	recv_database();
void	load_database();
void	send_error();
void	recv_error();

static void usage()
{
	fprintf(stderr,
		"\nUsage: %s [-r realm] [-s srvtab] [-dS] [-f slave_file]\n",
		progname);
	fprintf(stderr, "\t[-F kerberos_db_file ] [-p kdb5_edit_pathname]\n\n",
		progname);
	exit(1);
}

void
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
	struct	sockaddr_in	sin, frominet;
	struct servent *sp;
	int	finet, fromlen, s;
	
	finet = socket(AF_INET, SOCK_STREAM, 0);
	if (finet < 0) {
		com_err(progname, errno, "while obtaining socket");
		exit(1);
	}
	sp = getservbyname(KPROP_SERVICE, "tcp");
	if (sp == NULL) {
		com_err(progname, 0, "%s/tcp: unknown service", KPROP_SERVICE);
		exit(1);
	}
	memset((char *) &sin,0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = sp->s_port;
	if (bind(finet, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		perror("bind");
		com_err(progname, errno, "while binding listener socket");
		exit(1);
	}
	if (!debug)
		detach_process();
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
		memset((char *)&frominet, 0, sizeof(frominet));
		fromlen = sizeof(frominet);
		s = accept(finet, (struct sockaddr *) &frominet, &fromlen);

		if (s < 0) {
			if (errno != EINTR)
				com_err(progname, errno,
					"from accept system call");
			continue;
		}
		if (debug || fork() == 0) {
			(void) signal(SIGCHLD, SIG_IGN);
			(void) close(finet);

			doit(s);
			close(s);
			exit(0);
		}
		close(s);
	}
}

void doit(fd)
	int	fd;
{
	struct sockaddr_in from;
	int on = 1, fromlen;
	struct hostent	*hp;
	krb5_error_code	retval;
	int	lock_fd;

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
	kerberos_authenticate(fd, &client, from);
	if (!authorized_principal(client)) {
		char	*name;

		if (retval = krb5_unparse_name(client, &name)) {
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
	if (debug) {
		printf("My sequence number: %d\n", my_seq_num);
		printf("His sequence number: %d\n", his_seq_num);
	}
	if ((lock_fd = (open(temp_file_name, O_WRONLY | O_CREAT, 0600))) < 0) {
		com_err(progname, errno,
			"while opening database file, '%s'",
			temp_file_name);
		exit(1);
	}
#ifdef POSIX_FILE_LOCKS
	{
		int lock_cmd = F_SETLK;
		struct flock lock_arg;

		lock_arg.l_type = F_WRLCK;
		lock_arg.l_whence = 0;
		lock_arg.l_start = 0;
		lock_arg.l_len = 0;
		
		if (fcntl(lock_fd, lock_cmd, &lock_arg) == -1) {
			/* see POSIX/IEEE 1003.1-1988, 6.5.2.4 */
			if (errno == EACCES || errno == EAGAIN)
				errno = EAGAIN;
			com_err(progname, errno, "while trying to lock '%s'",
				temp_file_name);
		}
	}
#else
	if (flock(lock_fd, LOCK_EX | LOCK_NB)) {
		com_err(progname, errno, "while trying to lock '%s'",
			temp_file_name);
		exit(1);
	}
#endif
	if ((database_fd = open(temp_file_name,
				O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
		com_err(progname, errno,
			"while opening database file, '%s'",
			temp_file_name);
		exit(1);
	}
	recv_database(fd, database_fd);
	if (close(fd) < 0) {
		com_err(progname, errno,
			"while trying to close database file");
		exit(1);
	}
	if (rename(temp_file_name, file)) {
		com_err(progname, errno, "While renaming %s to %s",
			temp_file_name, file);
		exit(1);
	}
	load_database(kdb5_edit, file);
	close(lock_fd);
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
	char	*cp;
	struct hostent *hp;
	char	my_host_name[MAXHOSTNAMELEN], buf[BUFSIZ];
	krb5_error_code	retval;
	static const char	tmp[] = ".temp";
	
	krb5_init_ets();

	progname = *argv++;
	while (word = *argv++) {
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
						kdb5_edit = word;
					else
						kdb5_edit = *argv++;
					if (!kdb5_edit)
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
	openlog("kpropd", LOG_PID | LOG_ODELAY, SYSLOG_CLASS);
	set_com_err_hook(kpropd_com_err_proc);
	/*
	 * Get my hostname, so we can construct my service name
	 */
	if (gethostname (my_host_name, sizeof(my_host_name)) != 0) { 
		com_err(progname, errno, "while getting my hostname");
		exit(1);
	}
	if (!(hp = gethostbyname(my_host_name))) {
		fprintf(stderr, "Couldn't get my cannonicalized host name!\n");
		exit(1);
	}
	for (cp=hp->h_name; *cp; cp++)
		if (isupper(*cp))
			*cp = tolower(*cp);
	if (realm)
		sprintf(buf, "%s/%s@%s", KPROP_SERVICE_NAME, hp->h_name,
			realm);
	else
		sprintf(buf, "%s/%s", KPROP_SERVICE_NAME, hp->h_name);
	if (retval = krb5_parse_name(buf, &server)) {
		com_err(progname, retval,
			"While trying to parse %s for service name");
		exit(1);
	}
	if (retval = krb5_os_localaddr(&server_addrs)) {
		com_err(progname, retval,
			"While trying to get local server address");
		exit(1);
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

void
detach_process()
{
	int	n;
	
#if defined(BSD) && BSD >= 199006 
	daemon(1, 0);
#else
	if (fork() > 0)
		exit(0);
	n = open("/dev/null", O_RDONLY);
	(void) dup2(n, 0);
	(void) dup2(n, 1);
	(void) dup2(n, 2);
	if (n > 2)
		(void) close(n);
#ifdef SYSV
	setpgrp();
#else
	{
		/*
		 * The open below may hang on pseudo ttys if the person
		 * who starts named logs out before this point.  Thus,
		 * the need for the timer.
		 */
		alarm(120);
		n = open("/dev/tty", O_RDWR);
		alarm(0);
		if (n > 0) {
			(void) ioctl(n, TIOCNOTTY, (char *)NULL);
			(void) close(n);
		}
	}
#endif /* SYSV */
#endif /* BSD > 199006 */
}

/*
 * Figure out who's calling on the other end of the connection....
 */
void
kerberos_authenticate(fd, clientp, sin)
	int	fd;
	krb5_principal	*clientp;
	struct sockaddr_in	sin;
{
	krb5_error_code	retval;
	krb5_ticket	*ticket;
	krb5_authenticator	*authent;
	struct sockaddr_in	r_sin;
	int			sin_length;

	/*
	 * Set recv_addr and send_addr
	 */
	sender_addr.addrtype = ADDRTYPE_INET;
	sender_addr.length = sizeof(sin.sin_addr);
	sender_addr.contents = (krb5_octet *) malloc(sizeof(sin.sin_addr));
	memcpy((char *) sender_addr.contents, (char *) &sin.sin_addr,
	       sizeof(sin.sin_addr));

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
		if (retval = krb5_unparse_name(server, &name)) {
			com_err(progname, retval,
				"While unparsing client name");
			exit(1);
		}
		printf("krb5_recvauth(%d, %s, %s, ...)\n", fd,
		       kprop_version, name);
		free(name);
	}

	if (retval = krb5_recvauth((void *) &fd, kprop_version, server,
				   &sender_addr, kerb_keytab, NULL, NULL,
				   "dfl", 0, &my_seq_num, clientp, &ticket,
				   &authent)) {
		syslog(LOG_ERR, "Error in krb5_recvauth: %s",
		       error_message(retval));
		exit(1);
	}
	if (debug) {
		char	*name;

		if (retval = krb5_unparse_name(*clientp, &name)) {
			com_err(progname, retval,
				"While unparsing client name");
			exit(1);
		}
		printf("authenticated client: %s\n", name);
		free(name);
	}
	his_seq_num = authent->seq_number;
	krb5_copy_keyblock(ticket->enc_part2->session, &session_key);
	krb5_free_ticket(ticket);
	krb5_free_authenticator(authent);
}

krb5_boolean
authorized_principal(p)
	krb5_principal	p;
{
    char		*name;
    char		buf[1024];
    krb5_error_code	retval;
    FILE		*acl_file;
    int			end;
    
    retval = krb5_unparse_name(p, &name);
    if (retval)
	return FALSE;

    acl_file = fopen(KPROPD_ACL_FILE, "r");
    if (!acl_file)
	return FALSE;

    while (!feof(acl_file)) {
	if (!fgets(buf, sizeof(buf), acl_file))
	    break;
	end = strlen(buf) - 1;
	if (buf[end] == '\n')
	    buf[end] = '\0';
	if (!strcmp(name, buf)) {
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
recv_database(fd, database_fd)
	int	fd;
	int	database_fd;
{
	int	database_size;
	int	received_size, n;
	char		buf[1024];
	char		*i_vector;
	krb5_data	inbuf, outbuf;
	krb5_error_code	retval;
	int		eblock_size;

	/*
	 * Receive and decode size from client
	 */
	if (retval = krb5_read_message((void *) &fd, &inbuf)) {
		send_error(fd, retval, "while reading database size");
		com_err(progname, retval,
			"while reading size of database from client");
		exit(1);
	}
	if (krb5_is_krb_error(&inbuf))
		recv_error(&inbuf);
	if (retval = krb5_rd_safe(&inbuf, session_key, &sender_addr,
				  &receiver_addr, his_seq_num++,
				  KRB5_SAFE_DOSEQUENCE|KRB5_SAFE_NOTIME,
				  0, &outbuf)) {
		send_error(fd, retval, "while decoding database size");
		krb5_xfree(inbuf.data);
		com_err(progname, retval,
			"while decoding database size from client");
		exit(1);
	}
	memcpy((char *) &database_size, outbuf.data, sizeof(database_size));
	krb5_xfree(inbuf.data);
	krb5_xfree(outbuf.data);
	database_size = ntohl(database_size);
	/*
	 * Initialize the initial vector.
	 */
	eblock_size = krb5_keytype_array[session_key->keytype]->
		system->block_length;
	if (!(i_vector=malloc(eblock_size))) {
		com_err(progname, ENOMEM, "while allocating i_vector");
		send_error(fd, ENOMEM,
			   "malloc failed while allocating i_vector");
		exit(1);
	}
	memset(i_vector, 0, eblock_size);
	/*
	 * Now start receiving the database from the net
	 */
	received_size = 0;
	while (received_size < database_size) {
		if (retval = krb5_read_message((void *) &fd, &inbuf)) {
			sprintf(buf,
				"while reading database block starting at offset %d",
				received_size);
			com_err(progname, retval, buf);
			send_error(fd, retval, buf);
			exit(1);
		}
		if (krb5_is_krb_error(&inbuf))
			recv_error(&inbuf);
		if (retval = krb5_rd_priv(&inbuf, session_key,
					  &sender_addr, &receiver_addr,
					  his_seq_num++,
					  KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
					  i_vector, 0, &outbuf)) {
			sprintf(buf,
				"while decoding database block starting at offset %d",
				received_size);
			com_err(progname, retval, buf);
			send_error(fd, retval, buf);
			krb5_xfree(inbuf.data);
			exit(1);
		}
		n = write(database_fd, outbuf.data, outbuf.length);
		krb5_xfree(inbuf.data);
		krb5_xfree(outbuf.data);
		if (n < 0) {
			sprintf(buf,
				"while writing database block starting at offset %d",
				received_size);
			send_error(fd, errno, buf);
		} else if (n != outbuf.length) {
			sprintf(buf,
				"incomplete write while writing database block starting at \noffset %d (%d written, %d expected)",
				received_size, n, outbuf.length);
			send_error(fd, KRB5KRB_ERR_GENERIC, buf);
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
		send_error(fd, KRB5KRB_ERR_GENERIC, buf);
	}
	/*
	 * Send over acknowledgement of number of bytes receieved.
	 */
	database_size = htonl(database_size);
	inbuf.data = (char *) &database_size;
	inbuf.length = sizeof(database_size);
	if (retval = krb5_mk_safe(&inbuf, KPROP_CKSUMTYPE,
				  session_key,
				  /* Note these are reversed because */
				  /* we are sending, not receiving! */
				  &receiver_addr, &sender_addr, 
				  my_seq_num++,
				  KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
				  0,	/* no rcache when NOTIME */
				  &outbuf)) {
		com_err(progname, retval,
			"while encoding # of receieved bytes");
		send_error(fd, retval,
			   "while encoding # of received bytes");
		exit(1);
	}
	if (retval = krb5_write_message((void *) &fd, &outbuf)) {
		krb5_xfree(outbuf.data);
		com_err(progname, retval,
			"while sending # of receeived bytes");
		exit(1);
	}
	krb5_xfree(outbuf.data);
}


void
send_error(fd, err_code, err_text)
	int	fd;
	char	*err_text;
	krb5_error_code	err_code;
{
	krb5_error	error;
	const char	*text;
	krb5_data	outbuf;
	char		buf[1024];

	memset((char *)&error, 0, sizeof(error));
	krb5_us_timeofday(&error.stime, &error.susec);
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
	if (error.text.data = malloc(error.text.length)) {
		strcpy(error.text.data, text);
		if (!krb5_mk_error(&error, &outbuf)) {
			(void) krb5_write_message((void *) &fd, &outbuf);
			krb5_xfree(outbuf.data);
		}
		free(error.text.data);
	}
}

void
recv_error(inbuf)
	krb5_data	*inbuf;
{
	krb5_error	*error;
	krb5_error_code	retval;

	if (retval = krb5_rd_error(inbuf, &error)) {
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
		com_err(progname, error->error + ERROR_TABLE_BASE_krb5,
			"signalled from server");
		if (error->text.data)
			fprintf(stderr,
				"Error text from client: %s\n",
				error->text.data);
	}
	krb5_free_error(error);
	exit(1);
}

void
load_database(kdb5_edit, database_file_name)
	char	*kdb5_edit;
	char	*database_file_name;
{
	static char	*edit_av[4];
	int	error_ret, save_stderr;

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
	char	request[1024];
	krb5_error_code	retval;

	if (debug)
		printf("calling krb5_edit to load database\n");

	sprintf(request, "load_db %s %s", database_file_name, kerb_database);
	
	edit_av[0] = kdb5_edit;
	edit_av[1] = "-R";	
	edit_av[2] = request;
	edit_av[3] = NULL;

#ifndef BSD
#define	vfork fork
#endif
	switch(vfork()) {
	case -1:
		com_err(progname, errno, "while trying to fork %s",
			kdb5_edit);
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

		execv(kdb5_edit, edit_av);
		retval = errno;
		if (!debug)
			dup2(save_stderr, 2);
		com_err(progname, retval, "while trying to exec %s",
			kdb5_edit);
		exit(1);
		/*NOTREACHED*/
	default:
		if (wait(&waitb) < 0) {
			com_err(progname, errno, "while waiting for %s",
				kdb5_edit);
			exit(1);
		}
	}
	
	if (error_ret = WEXITSTATUS(waitb)) {
		com_err(progname, 0, "%s returned a bad exit status (%d)",
			kdb5_edit, error_ret);
		exit(1);
	}
	return;
}
