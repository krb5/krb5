/*
 * slave/kprop.c
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
 */


#include <errno.h>
#ifdef POSIX_FILE_LOCKS
#include <fcntl.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <sys/file.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <netdb.h>

#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/osconf.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <com_err.h>

#ifdef NEED_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif

#include "kprop.h"

static char *kprop_version = KPROP_PROT_VERSION;

char	*progname = 0;
int     debug = 0;
char	*slave_host;
char	*realm = 0;
char	*file = KPROP_DEFAULT_FILE;

krb5_principal	my_principal;		/* The Kerberos principal we'll be */
				/* running under, initialized in */
				/* get_tickets() */
krb5_ccache	ccache;		/* Credentials cache which we'll be using */
krb5_creds 	my_creds;	/* My credentials */
krb5_int32	my_seq_num;	/* Sequence number to use for connection */
krb5_int32	his_seq_num;	/* Remote sequence number */
krb5_address	sender_addr;
krb5_address	receiver_addr;

void	PRS();
void	get_tickets();
static void usage();
krb5_error_code open_connection();
void	kerberos_authenticate();
int	open_database();
void	xmit_database();
void	send_error();
void	update_last_prop_file();

static void usage()
{
	fprintf(stderr, "\nUsage: %s [-r realm] [-f file] [-d] slave_host\n\n",
		progname);
	exit(1);
}

void
main(argc, argv)
	int	argc;
	char	**argv;
{
	int	fd, database_fd, database_size;
	krb5_error_code	retval;
	char	Errmsg[256];
	
	PRS(argv);
	get_tickets();

	database_fd = open_database(file, &database_size);
	if (retval = open_connection(slave_host, &fd, Errmsg)) {
		com_err(progname, retval, "%s while opening connection to %s",
			Errmsg, slave_host);
		exit(1);
	}
	if (fd < 0) {
		fprintf(stderr, "%s: %s while opening connection to %s\n",
			progname, Errmsg, slave_host);
		exit(1);
	}
	kerberos_authenticate(fd, my_principal);
	if (debug) {
		printf("My sequence number: %d\n", my_seq_num);
		printf("His sequence number: %d\n", his_seq_num);
	}
	xmit_database(fd, database_fd, database_size);
	update_last_prop_file(slave_host, file);
	printf("Database propagation to %s: SUCCEEDED\n", slave_host);
	exit(0);
}

void PRS(argv)
	char	**argv;
{
	register char	*word, ch;
	
	krb5_init_ets();
	progname = *argv++;
	while (word = *argv++) {
		if (*word == '-') {
			word++;
			while (word && (ch = *word++)) {
				switch(ch){
				case 'r':
					if (*word)
						realm = word;
					else
						realm = *argv++;
					if (!realm)
						usage();
					word = 0;
					break;
				case 'f':
					if (*word)
						file = word;
					else
						file = *argv++;
					if (!file)
						usage();
					word = 0;
					break;
				case 'd':
					debug++;
					break;
				default:
					usage();
				}
				
			}
		} else {
			if (slave_host)
				usage();
			else
				slave_host = word;
		}
	}
	if (!slave_host)
		usage();
}

void get_tickets()
{
	char   my_host_name[MAXHOSTNAMELEN];
	char   buf[BUFSIZ];
	char   *cp;
	struct hostent *hp;
	krb5_address **my_addresses;
	krb5_error_code retval;
	static char tkstring[] = "/tmp/kproptktXXXXXX";

	/*
	 * Figure out what tickets we'll be using to send stuff
	 */
	if (gethostname (my_host_name, sizeof(my_host_name)) != 0) { 
		com_err(progname, errno, "while getting my hostname");
		exit(1);
	}
	/* get canonicalized  service instance name */
	if (!(hp = gethostbyname(my_host_name))) {
		fprintf(stderr, "Couldn't get my cannonicalized host name!\n");
		exit(1);
	}
	for (cp=hp->h_name; *cp; cp++)
		if (isupper(*cp))
			*cp = tolower(*cp);
	if (realm)
		sprintf(buf, "host/%s@%s", hp->h_name, realm);
	else
		sprintf(buf, "host/%s", hp->h_name);
	if (retval = krb5_parse_name(buf, &my_principal)) {
		com_err (progname, retval, "when parsing name %s",buf);
		exit(1);
	}

	/*
	 * Initialize cache file which we're going to be using
	 */
	(void) mktemp(tkstring);
	sprintf(buf, "FILE:%s", tkstring);
	if (retval = krb5_cc_resolve(buf, &ccache)) {
		com_err(progname, retval, "while opening crednetials cache %s",
			buf);
		exit(1);
	}
	if (retval = krb5_cc_initialize(ccache, my_principal)) {
		com_err (progname, retval, "when initializing cache %s",
			 buf);
		exit(1);
	}

	/*
	 * Get the tickets we'll need.
	 *
	 * Construct the principal name for the slave host.
	 */
	memset((char *)&my_creds, 0, sizeof(my_creds));
	if (!(hp = gethostbyname(slave_host))) {
		fprintf(stderr,
			"Couldn't get cannonicalized name for slave\n");
		exit(1);
	}
	for (cp=hp->h_name; *cp; cp++)
		if (isupper(*cp))
			*cp = tolower(*cp);
	if (!(slave_host = malloc(strlen(hp->h_name) + 1))) {
		com_err(progname, ENOMEM,
			"while allocate space for canonicalized slave host");
		exit(1);
	}
	strcpy(slave_host, hp->h_name);
	if (realm)
		sprintf(buf, "%s/%s@%s", KPROP_SERVICE_NAME, slave_host,
			realm);
	else
		sprintf(buf, "%s/%s", KPROP_SERVICE_NAME, hp->h_name);
	if (retval = krb5_parse_name(buf, &my_creds.server)) {
		com_err(progname, retval,
			"while parsing slave principal name");
		exit(1);
	}
	/*
	 * Now fill in the client....
	 */
	if (retval = krb5_copy_principal(my_principal, &my_creds.client)) {
		com_err(progname, retval, "While copying client principal");
		exit(1);
	}
	/*
	 * Get my addresses
	 */
	retval = krb5_os_localaddr(&my_addresses);
	if (retval != 0) {
		com_err(progname, retval,
			"when getting my address");
		exit(1);
	}
	retval = krb5_get_in_tkt_with_skey(0, my_addresses,
					   0,
					   ETYPE_DES_CBC_CRC,
					   0, ccache, &my_creds, 0);
	if (retval) {
		com_err(progname, retval, "while getting initial ticket\n");
		exit(1);
	}
	/*
	 * Now destroy the cache right away --- the credentials we
	 * need will be in my_creds.
	 */
	if (retval = krb5_cc_destroy(ccache)) {
		com_err(progname, retval, "while destroying ticket cache");
		exit(1);
	}
}

krb5_error_code
open_connection(host, fd, Errmsg)
	char	*host;
	int	*fd;
	char	*Errmsg;
{
	int	s;
	krb5_error_code	retval;
	
	struct hostent	*hp;
	register struct servent *sp;
	struct sockaddr_in sin;
	int		socket_length;

	hp = gethostbyname(host);
	if (hp == NULL) {
		(void) sprintf(Errmsg, "%s: unknown host", host);
		*fd = -1;
		return(0);
	}
	sp = getservbyname(KPROP_SERVICE, "tcp");
	if (sp == 0) {
		(void) strcpy(Errmsg, KPROP_SERVICE);
		(void) strcat(Errmsg, "/tcp: unknown service");
		*fd = -1;
		return(0);
	}
	sin.sin_family = hp->h_addrtype;
	memcpy((char *)&sin.sin_addr, hp->h_addr, hp->h_length);
	sin.sin_port = sp->s_port;
	s = socket(AF_INET, SOCK_STREAM, 0);
	
	if (s < 0) {
		(void) sprintf(Errmsg, "in call to socket");
		return(errno);
	}
	if (connect(s, (struct sockaddr *)&sin, sizeof sin) < 0) {
		retval = errno;
		close(s);
		(void) sprintf(Errmsg, "in call to connect");
		return(retval);
	}
	*fd = s;

	/*
	 * Set receiver_addr and sender_addr.
	 */
	receiver_addr.addrtype = ADDRTYPE_INET;
	receiver_addr.length = sizeof(sin.sin_addr);
	receiver_addr.contents = (krb5_octet *) malloc(sizeof(sin.sin_addr));
	memcpy((char *) receiver_addr.contents, (char *) &sin.sin_addr,
	       sizeof(sin.sin_addr));

	socket_length = sizeof(sin);
	if (getsockname(s, (struct sockaddr *)&sin, &socket_length) < 0) {
		retval = errno;
		close(s);
		(void) sprintf(Errmsg, "in call to getsockname");
		return(retval);
	}
	sender_addr.addrtype = ADDRTYPE_INET;
	sender_addr.length = sizeof(sin.sin_addr);
	sender_addr.contents = (krb5_octet *) malloc(sizeof(sin.sin_addr));
	memcpy((char *) sender_addr.contents, (char *) &sin.sin_addr,
	       sizeof(sin.sin_addr));

	return(0);
}


void kerberos_authenticate(fd, me)
	int	fd;
	krb5_principal	me;
{
	krb5_error_code	retval;
	krb5_error	*error = NULL;
	krb5_ap_rep_enc_part	*rep_result;

	if (retval = krb5_sendauth((void *)&fd, kprop_version, me,
				   my_creds.server, AP_OPTS_MUTUAL_REQUIRED,
				   NULL, &my_creds, NULL, &my_seq_num, NULL,
				   &error, &rep_result)) {
		com_err(progname, retval, "while authenticating to server");
		if (error) {
			if (error->error == KRB_ERR_GENERIC) {
				if (error->text.data)
					fprintf(stderr,
						"Generic remote error: %s\n",
						error->text.data);
			} else if (error->error) {
				com_err(progname,
					error->error + ERROR_TABLE_BASE_krb5,
					"signalled from server");
				if (error->text.data)
					fprintf(stderr,
						"Error text from server: %s\n",
						error->text.data);
			}
			krb5_free_error(error);
		}
		exit(1);
	}
	his_seq_num = rep_result->seq_number;
	krb5_free_ap_rep_enc_part(rep_result);
}

/*
 * Open the Kerberos database dump file.  Takes care of locking it
 * and making sure that the .ok file is more recent that the database
 * dump file itself.
 *
 * Returns the file descriptor of the database dump file.  Also fills
 * in the size of the database file.
 */
int
open_database(data_fn, size)
	char	*data_fn;
	int	*size;
{
	int		fd;
	struct stat 	stbuf, stbuf_ok;
	char		*data_ok_fn;
	static char ok[] = ".dump_ok";
#ifdef POSIX_FILE_LOCKS
	struct flock lock_arg;
#endif

	if ((fd = open(data_fn, O_RDONLY)) < 0) {
		com_err(progname, errno, "while trying to open %s",
			data_fn);
		exit(1);
	}
	
#ifdef POSIX_FILE_LOCKS
	lock_arg.l_whence = 0;
	lock_arg.l_start = 0;
	lock_arg.l_len = 0;
	if (fcntl(fd, F_SETLK, &lock_arg) == -1) {
		if (errno == EACCES || errno == EAGAIN)
			com_err(progname, 0, "database locked");
		else
			com_err(progname, errno, "while trying to flock %s",
				data_fn);
		exit(1);
	}
#else
	if (flock(fd, LOCK_SH | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			com_err(progname, 0, "database locked");
		else
			com_err(progname, errno, "while trying to flock %s",
				data_fn);
		exit(1);
	}
#endif
	if (fstat(fd, &stbuf)) {
		com_err(progname, errno, "while trying to stat %s",
			data_fn);
		exit(1);
	}
	if ((data_ok_fn = (char *) malloc(strlen(data_fn)+strlen(ok)+1))
	    == NULL) {
		com_err(progname, ENOMEM, "while trying to malloc data_ok_fn");
		exit(1);
	}
	strcat(strcpy(data_ok_fn, data_fn), ok);
	if (stat(data_ok_fn, &stbuf_ok)) {
		com_err(progname, errno, "while trying to stat %s",
			data_ok_fn);
		free(data_ok_fn);
		exit(1);
	}
	free(data_ok_fn);
	if (stbuf.st_mtime > stbuf_ok.st_mtime) {
		com_err(progname, 0, "'%s' more recent than '%s'.",
			data_fn, data_ok_fn);
		exit(1);
	}
	*size = stbuf.st_size;
	return(fd);
}

/*
 * Now we send over the database.  We use the following protocol:
 * Send over a KRB_SAFE message with the size.  Then we send over the
 * database in blocks of KPROP_BLKSIZE, encrypted using KRB_PRIV.
 * Then we expect to see a KRB_SAFE message with the size sent back.
 * 
 * At any point in the protocol, we may send a KRB_ERROR message; this
 * will abort the entire operation.
 */
void
xmit_database(fd, database_fd, database_size)
	int	fd;
	int	database_fd;
	int	database_size;
{
	int	send_size, sent_size, n, eblock_size;
	krb5_data	inbuf, outbuf;
	char		buf[KPROP_BUFSIZ];
	char		*i_vector;
	krb5_error_code	retval;
	krb5_error	*error;
	
	/*
	 * Send over the size
	 */
	send_size = htonl(database_size);
	inbuf.data = (char *) &send_size;
	inbuf.length = sizeof(send_size); /* must be 4, really */
	if (retval = krb5_mk_safe(&inbuf, KPROP_CKSUMTYPE,
				  &my_creds.keyblock, 
				  &sender_addr, &receiver_addr,
				  my_seq_num++,
				  KRB5_PRIV_DOSEQUENCE|KRB5_SAFE_NOTIME,
				  0,	/* no rcache when NOTIME */
				  &outbuf)) {
		com_err(progname, retval, "while encoding database size");
		send_error(fd, "while encoding database size", retval);
		exit(1);
	}
	if (retval = krb5_write_message((void *) &fd, &outbuf)) {
		krb5_xfree(outbuf.data);
		com_err(progname, retval, "while sending database size");
		exit(1);
	}
	krb5_xfree(outbuf.data);
	/*
	 * Initialize the initial vector.
	 */
	eblock_size = krb5_keytype_array[my_creds.keyblock.keytype]->
		system->block_length;
	if (!(i_vector=malloc(eblock_size))) {
		com_err(progname, ENOMEM, "while allocating i_vector");
		send_error(fd, "malloc failed while allocating i_vector",
			   ENOMEM);
		exit(1);
	}
	memset(i_vector, 0, eblock_size);
	/*
	 * Send over the file, block by block....
	 */
	inbuf.data = buf;
	sent_size = 0;
	while (n = read(database_fd, buf, sizeof(buf))) {
		inbuf.length = n;
		if (retval = krb5_mk_priv(&inbuf, ETYPE_DES_CBC_CRC,
					  &my_creds.keyblock,
					  &sender_addr,
					  &receiver_addr,
					  my_seq_num++,
					  KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
					  0, /* again, no rcache */
					  i_vector,
					  &outbuf)) {
			sprintf(buf,
				"while encoding database block starting at %d",
				sent_size);
			com_err(progname, retval, buf);
			send_error(fd, buf, retval);
			exit(1);
		}
		if (retval = krb5_write_message((void *) &fd, &outbuf)) {
			krb5_xfree(outbuf.data);
			com_err(progname, retval,
				"while sending database block starting at %d",
				sent_size);
			exit(1);
		}
		krb5_xfree(outbuf.data);
		sent_size += n;
		if (debug)
			printf("%d bytes sent.\n", sent_size);
	}
	if (sent_size != database_size) {
		com_err(progname, 0, "Premature EOF found for database file!");
		send_error(fd, "Premature EOF found for database file!",
			   KRB5KRB_ERR_GENERIC);
		exit(1);
	}
	/*
	 * OK, we've sent the database; now let's wait for a success
	 * indication from the remote end.
	 */
	if (retval = krb5_read_message((void *) &fd, &inbuf)) {
		com_err(progname, retval,
			"while reading response from server");
		exit(1);
	}
	/*
	 * If we got an error response back from the server, display
	 * the error message
	 */
	if (krb5_is_krb_error(&inbuf)) {
		if (retval = krb5_rd_error(&inbuf, &error)) {
			com_err(progname, retval,
				"while decoding error response from server");
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
					"Error text from server: %s\n",
					error->text.data);
		}
		krb5_free_error(error);
		exit(1);
	}
	if (retval = krb5_rd_safe(&inbuf, &my_creds.keyblock, &receiver_addr,
				  &sender_addr, his_seq_num++,
				  KRB5_SAFE_DOSEQUENCE|KRB5_SAFE_NOTIME,
				  0, &outbuf)) {
		com_err(progname, retval,
			"while decoding final size packet from server");
		exit(1);
	}
	memcpy((char *)&send_size, outbuf.data, sizeof(send_size));
	send_size = ntohl(send_size);
	if (send_size != database_size) {
		com_err(progname, 0,
			"Kpropd sent database size %d, expecting %d",
			send_size, database_size);
		exit(1);
	}
	free(outbuf.data);
	free(inbuf.data);
}

void
send_error(fd, err_text, err_code)
	int	fd;
	char	*err_text;
	krb5_error_code	err_code;
{
	krb5_error	error;
	const char	*text;
	krb5_data	outbuf;

	memset((char *)&error, 0, sizeof(error));
	krb5_us_timeofday(&error.ctime, &error.cusec);
	error.server = my_creds.server;
	error.client = my_principal;
	error.error = err_code - ERROR_TABLE_BASE_krb5;
	if (error.error > 127)
		error.error = KRB_ERR_GENERIC;
	if (err_text)
		text = err_text;
	else
		text = error_message(err_code);
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

void update_last_prop_file(hostname, file_name)
	char *hostname;
	char *file_name;
{
	/* handle slave locking/failure stuff */
	char *file_last_prop;
	int fd;
	static char last_prop[]=".last_prop";

	if ((file_last_prop = (char *)malloc(strlen(file_name) +
					     strlen(hostname) + 1 +
					     strlen(last_prop) + 1)) == NULL) {
		com_err(progname, ENOMEM,
			"while allocating filename for update_last_prop_file");
		return;
	}
	strcpy(file_last_prop, file_name);
	strcat(file_last_prop, ".");
	strcat(file_last_prop, hostname);
	strcat(file_last_prop, last_prop);
	if ((fd = open(file_last_prop, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
		com_err(progname, errno,
			"while creating 'last_prop' file, '%s'",
			file_last_prop);
		free(file_last_prop);
		return;
	}
	free(file_last_prop);
	close(fd);
	return;
}
