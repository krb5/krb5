/*
 * appl/bsd/kcmd.c
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* derived from @(#)rcmd.c	5.17 (Berkeley) 6/27/88 */
     
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <sys/param.h>
#ifndef _TYPES_
#include <sys/types.h>
#define _TYPES_
#endif
#include <fcntl.h>
     
#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>

#ifndef POSIX_SIGNALS
#ifndef sigmask
#define sigmask(m)    (1 << ((m)-1))
#endif
#endif
     
#ifndef roundup
#define roundup(x,y) ((((x)+(y)-1)/(y))*(y))
#endif

#include <netinet/in.h>
#include <netdb.h>
     
#include <errno.h>
#include <krb5.h>
#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#endif

#include "defines.h"

extern krb5_context bsd_context;
#ifdef KRB5_KRB4_COMPAT
extern Key_schedule v4_schedule;
#endif

#define RCMD_BUFSIZ	5120
#define START_PORT      5120     /* arbitrary */
char *default_service = "host";

#define KCMD_KEYUSAGE	1026

/*
 * Note that the encrypted rlogin packets take the form of a four-byte
 * length followed by encrypted data.  On writing the data out, a significant
 * performance penalty is suffered (at least one RTT per character, two if we
 * are waiting for a shell to echo) by writing the data separately from the 
 * length.  So, unlike the input buffer, which just contains the output
 * data, the output buffer represents the entire packet.
 */

static char des_inbuf[2*RCMD_BUFSIZ];	 /* needs to be > largest read size */
static char des_outpkt[2*RCMD_BUFSIZ+4]; /* needs to be > largest write size */
static krb5_data desinbuf;
static krb5_data desoutbuf;
static krb5_data encivec;
static krb5_keyblock *keyblock;		 /* key for encrypt/decrypt */
static int (*input)();
static int (*output)();
static char storage[2*RCMD_BUFSIZ];	 /* storage for the decryption */
static int nstored = 0;
static char *store_ptr = storage;
static int twrite();
static int v5_des_read(), v5_des_write();
#ifdef KRB5_KRB4_COMPAT
static int v4_des_read(), v4_des_write();
static C_Block v4_session;
static int right_justify;
static int do_lencheck;
#endif

kcmd(sock, ahost, rport, locuser, remuser, cmd, fd2p, service, realm,
     cred, seqno, server_seqno, laddr, faddr, authopts, anyport, suppress_err)
     int *sock;
     char **ahost;
     u_short rport;
     char *locuser, *remuser, *cmd;
     int *fd2p;
     char *service;
     char *realm;
     krb5_creds **cred;
     krb5_int32 *seqno;
     krb5_int32 *server_seqno;
     struct sockaddr_in *laddr, *faddr;
     krb5_flags authopts;
     int anyport;
     int suppress_err;		/* Don't print if authentication fails */
{
    int i, s, timo = 1, pid;
#ifdef POSIX_SIGNALS
    sigset_t oldmask, urgmask;
#else
    long oldmask;
#endif
    struct sockaddr_in sin, from, local_laddr;
    krb5_creds *get_cred, *ret_cred = 0;
    char c;
    int lport;
    struct hostent *hp;
    int rc;
    char *host_save;
    krb5_error_code status;
    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_error	*error = 0;
    int sin_len;
    krb5_ccache cc;
    krb5_data outbuf;
    krb5_flags options = authopts;
    krb5_auth_context auth_context = NULL;
    char *cksumbuf;
    krb5_data cksumdat;

    if ((cksumbuf = malloc(strlen(cmd)+strlen(remuser)+64)) == 0 ) {
	fprintf(stderr, "Unable to allocate memory for checksum buffer.\n");
	return(-1);
    }
    sprintf(cksumbuf, "%u:", ntohs(rport));
    strcat(cksumbuf, cmd);
    strcat(cksumbuf, remuser);
    cksumdat.data = cksumbuf;
    cksumdat.length = strlen(cksumbuf);
	
    pid = getpid();
    hp = gethostbyname(*ahost);
    if (hp == 0) {
	fprintf(stderr, "%s: unknown host\n", *ahost);
	return (-1);
    }
    
    if ((host_save = (char *) malloc(strlen(hp->h_name) + 1)) == NULL) {
        fprintf(stderr,"kcmd: no memory\n");
        return(-1);
    }

    strcpy(host_save, hp->h_name);

    /* If no service is given set to the default service */
    if (!service) service = default_service;
    
    sin_len = strlen(host_save) + strlen(service)
      + (realm ? strlen(realm): 0) + 3;
    if ( sin_len < 20 ) sin_len = 20;
    
    if (!(get_cred = (krb5_creds *)calloc(1, sizeof(krb5_creds)))) {
        fprintf(stderr,"kcmd: no memory\n");
        return(-1);
    }
    status = krb5_sname_to_principal(bsd_context, host_save, service,
				     KRB5_NT_SRV_HST, &get_cred->server);
    if (status) {
	    fprintf(stderr, "kcmd: krb5_sname_to_principal failed: %s\n",
		    error_message(status));
	    return(-1);
    }

    if (realm && *realm) {
	free(krb5_princ_realm(bsd_context,get_cred->server)->data);
	/*krb5_xfree(krb5_princ_realm(bsd_context,get_cred->server)->data);*/

	krb5_princ_set_realm_length(bsd_context,get_cred->server,strlen(realm));
	krb5_princ_set_realm_data(bsd_context,get_cred->server,strdup(realm));
   }
#ifdef POSIX_SIGNALS
    sigemptyset(&urgmask);
    sigaddset(&urgmask, SIGURG);
    sigprocmask(SIG_BLOCK, &urgmask, &oldmask);
#else
    oldmask = sigblock(sigmask(SIGURG));
#endif /* POSIX_SIGNALS */
    
    for (;;) {
        s = getport(0);
    	if (s < 0) {
	    if (errno == EAGAIN)
		fprintf(stderr, "socket: All ports in use\n");
	    else
		perror("kcmd: socket");
#ifdef POSIX_SIGNALS
	    sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
	    sigsetmask(oldmask);
#endif /* POSIX_SIGNALS */
	    krb5_free_creds(bsd_context, get_cred);
	    return (-1);
    	}
    	sin.sin_family = hp->h_addrtype;
    	memcpy((caddr_t)&sin.sin_addr,hp->h_addr, sizeof(sin.sin_addr));
    	sin.sin_port = rport;
    	if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0)
	    break;
    	(void) close(s);
    	if (errno == EADDRINUSE)
	    continue;

#if !(defined(tek) || defined(ultrix) || defined(sun) || defined(SYSV))
    	if (hp->h_addr_list[1] != NULL) {
	    int oerrno = errno;
	    
	    fprintf(stderr,
    		    "connect to address %s: ", inet_ntoa(sin.sin_addr));
	    errno = oerrno;
	    perror(0);
	    hp->h_addr_list++;
	    memcpy((caddr_t)&sin.sin_addr,hp->h_addr_list[0],
		   sizeof(sin.sin_addr));
	    fprintf(stderr, "Trying %s...\n",
		    inet_ntoa(sin.sin_addr));
	    continue;
    	}
#endif /* !(defined(ultrix) || defined(sun)) */
    	perror(host_save);
#ifdef POSIX_SIGNALS
	sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
    	sigsetmask(oldmask);
#endif /* POSIX_SIGNALS */
	krb5_free_creds(bsd_context, get_cred);
    	return (-1);
    }
    if (fd2p == 0) {
    	write(s, "", 1);
    	lport = 0;
    } else {
    	char num[8];
    	int s2 = getport(&lport), s3;
    	int len = sizeof (from);
	
    	if (s2 < 0) {
	    status = -1;
	    goto bad;
    	}
    	listen(s2, 1);
    	(void) sprintf(num, "%d", lport);
    	if (write(s, num, strlen(num)+1) != strlen(num)+1) {
	    perror("write: setting up stderr");
	    (void) close(s2);
	    status = -1;
	    goto bad;
    	}
    	s3 = accept(s2, (struct sockaddr *)&from, &len);
    	(void) close(s2);
    	if (s3 < 0) {
	    perror("accept");
	    lport = 0;
	    status = -1;
	    goto bad;
    	}
    	*fd2p = s3;
    	from.sin_port = ntohs((u_short)from.sin_port);
    	if (! anyport &&
	    (from.sin_family != AF_INET ||
    	     from.sin_port >= IPPORT_RESERVED)) {
	    fprintf(stderr,
    		    "socket: protocol failure in circuit setup.\n");
	    goto bad2;
    	}
    }
    
    if (!laddr) laddr = &local_laddr;
    if (!faddr) faddr = &sin;
    else 
      memcpy(faddr,&sin,sizeof(sin));
    
    sin_len = sizeof (struct sockaddr_in);
    if (getsockname(s, (struct sockaddr *)laddr, &sin_len) < 0) {
        perror("getsockname");
        status = -1;
        goto bad2;
    }

    if (status = krb5_cc_default(bsd_context, &cc))
    	goto bad2;

    if (status = krb5_cc_get_principal(bsd_context, cc, &get_cred->client)) {
    	(void) krb5_cc_close(bsd_context, cc);
    	goto bad2;
    }

    /* Get ticket from credentials cache or kdc */
    status = krb5_get_credentials(bsd_context, 0, cc, get_cred, &ret_cred);
    krb5_free_creds(bsd_context, get_cred);
    (void) krb5_cc_close(bsd_context, cc);
    if (status) goto bad2;

    /* Reset internal flags; these should not be sent. */
    authopts &= (~OPTS_FORWARD_CREDS);
    authopts &= (~OPTS_FORWARDABLE_CREDS);

    if (krb5_auth_con_init(bsd_context, &auth_context)) 
	goto bad2;

    if (krb5_auth_con_setflags(bsd_context, auth_context, 
			       KRB5_AUTH_CONTEXT_RET_TIME))
	goto bad2;

    /* Only need local address for mk_cred() to send to krlogind */
    if (status = krb5_auth_con_genaddrs(bsd_context, auth_context, s,
			KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR))
	goto bad2;

   /* call Kerberos library routine to obtain an authenticator,
       pass it over the socket to the server, and obtain mutual
       authentication. */
    status = krb5_sendauth(bsd_context, &auth_context, (krb5_pointer) &s,
                           "KCMDV0.1", ret_cred->client, ret_cred->server,
			   authopts, &cksumdat, ret_cred, 0,	&error, &rep_ret, NULL);
    free(cksumbuf);
    if (status) {
	if (!suppress_err)
	    fprintf(stderr, "Couldn't authenticate to server: %s\n",
		    error_message(status));
	if (error) {
	    if (!suppress_err) {
		fprintf(stderr, "Server returned error code %d (%s)\n",
			error->error,
			error_message(ERROR_TABLE_BASE_krb5 + error->error));
		if (error->text.length) {
		    fprintf(stderr, "Error text sent from server: %s\n",
			    error->text.data);
		}
	    }
	    krb5_free_error(bsd_context, error);
	    error = 0;
	}
    }	
    if (status) goto bad2;
    if (rep_ret && server_seqno) {
	*server_seqno = rep_ret->seq_number;
	krb5_free_ap_rep_enc_part(bsd_context, rep_ret);
    }
    
    (void) write(s, remuser, strlen(remuser)+1);
    (void) write(s, cmd, strlen(cmd)+1);
    (void) write(s, locuser, strlen(locuser)+1);
    
    if (options & OPTS_FORWARD_CREDS) {   /* Forward credentials */
	if (status = krb5_fwd_tgt_creds(bsd_context, auth_context,
					host_save,
					ret_cred->client, ret_cred->server,
					0, options & OPTS_FORWARDABLE_CREDS,
					&outbuf)) {
	    fprintf(stderr, "kcmd: Error getting forwarded creds\n");
	    goto bad2;
	}

	/* Send forwarded credentials */
	if (status = krb5_write_message(bsd_context, (krb5_pointer)&s, &outbuf))
	  goto bad2;
    }
    else { /* Dummy write to signal no forwarding */
	outbuf.length = 0;
	if (status = krb5_write_message(bsd_context, (krb5_pointer)&s, &outbuf))
	  goto bad2;
    }

    if ((rc=read(s, &c, 1)) != 1) {
	if (rc==-1) {
	    perror(*ahost);
	} else {
	    fprintf(stderr,"kcmd: bad connection with remote host\n");
	}
	status = -1;
	goto bad2;
    }
    if (c != 0) {
	while (read(s, &c, 1) == 1) {
	    (void) write(2, &c, 1);
	    if (c == '\n')
	      break;
	}
	status = -1;
	goto bad2;
    }
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
    sigsetmask(oldmask);
#endif /* POSIX_SIGNALS */
    *sock = s;
    
    /* pass back credentials if wanted */
    if (cred) krb5_copy_creds(bsd_context, ret_cred, cred);
    krb5_free_creds(bsd_context, ret_cred);
    
    return (0);
  bad2:
    if (lport)
      (void) close(*fd2p);
  bad:
    (void) close(s);
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
    sigsetmask(oldmask);
#endif /* POSIX_SIGNALS */
    if (ret_cred)
      krb5_free_creds(bsd_context, ret_cred);
    return (status);
}



#ifdef KRB5_KRB4_COMPAT
k4cmd(sock, ahost, rport, locuser, remuser, cmd, fd2p, ticket, service, realm,
      cred, schedule, msg_data, laddr, faddr, authopts, anyport)
     int *sock;
     char **ahost;
     u_short rport;
     char *locuser, *remuser, *cmd;
     int *fd2p;
     KTEXT ticket;
     char *service;
     char *realm;
     CREDENTIALS *cred;
     Key_schedule schedule;
     MSG_DAT *msg_data;
     struct sockaddr_in *laddr, *faddr;
     long authopts;
     int anyport;
{
    int s, pid;
#ifdef POSIX_SIGNALS
    sigset_t oldmask, urgmask;
#else
    sigmasktype oldmask;
#endif
    struct sockaddr_in sin, from;
    char c;
    int lport = START_PORT;
    struct hostent *hp;
    int rc, sin_len;
    char *host_save;
    int status;

    pid = getpid();
    hp = gethostbyname(*ahost);
    if (hp == 0) {
	fprintf(stderr, "%s: unknown host\n", *ahost);
	return (-1);
    }
    host_save = malloc(strlen(hp->h_name) + 1);
    strcpy(host_save, hp->h_name);
    *ahost = host_save;

    /* If realm is null, look up from table */
    if ((realm == NULL) || (realm[0] == '\0')) {
	realm = krb_realmofhost(host_save);
    }

#ifdef POSIX_SIGNALS
    sigemptyset(&urgmask);
    sigaddset(&urgmask, SIGURG);
    sigprocmask(SIG_BLOCK, &urgmask, &oldmask);
#else
    oldmask = sigblock(sigmask(SIGURG));
#endif /* POSIX_SIGNALS */
    for (;;) {
	s = getport(&lport);
	if (s < 0) {
	    if (errno == EAGAIN)
		fprintf(stderr, "socket: All ports in use\n");
	    else
		perror("rcmd: socket");
#ifdef POSIX_SIGNALS
	    sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
	    sigsetmask(oldmask);
#endif /* POSIX_SIGNALS */
	    return (-1);
	}
	sin.sin_family = hp->h_addrtype;
	memcpy((caddr_t)&sin.sin_addr, hp->h_addr, sizeof(sin.sin_addr));
	sin.sin_port = rport;
	if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0)
	    break;
	(void) close(s);
	if (errno == EADDRINUSE) {
	    lport--;
	    continue;
	}
#if !(defined(tex) || defined(ultrix) || defined(sun) || defined(SYSV))
	if (hp->h_addr_list[1] != NULL) {
	    int oerrno = errno;

	    fprintf(stderr,
		    "connect to address %s: ", inet_ntoa(sin.sin_addr));
	    errno = oerrno;
	    perror(0);
	    hp->h_addr_list++;
	    memcpy((caddr_t)&sin.sin_addr, hp->h_addr_list[0],
		   sizeof(sin.sin_addr));
	    fprintf(stderr, "Trying %s...\n", inet_ntoa(sin.sin_addr));
	    continue;
	}
#endif						/* !(defined(ultrix) || defined(sun)) */
	perror(host_save);
#ifdef POSIX_SIGNALS
	sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
	sigsetmask(oldmask);
#endif /* POSIX_SIGNALS */
	return (-1);
    }
    lport--;
    if (fd2p == 0) {
	write(s, "", 1);
	lport = 0;
    } else {
	char num[8];
	int s2 = getport(&lport), s3;
	int len = sizeof (from);

	if (s2 < 0) {
	    status = -1;
	    goto bad;
	}
	listen(s2, 1);
	(void) sprintf(num, "%d", lport);
	if (write(s, num, strlen(num)+1) != strlen(num)+1) {
	    perror("write: setting up stderr");
	    (void) close(s2);
	    status = -1;
	    goto bad;
	}
	s3 = accept(s2, (struct sockaddr *)&from, &len);
	(void) close(s2);
	if (s3 < 0) {
	    perror("accept");
	    lport = 0;
	    status = -1;
	    goto bad;
	}
	*fd2p = s3;
	from.sin_port = ntohs((u_short)from.sin_port);
	/* This check adds nothing when using Kerberos.  */
	if (! anyport &&
	    (from.sin_family != AF_INET ||
	     from.sin_port >= IPPORT_RESERVED)) {
	    fprintf(stderr, "socket: protocol failure in circuit setup.\n");
	    status = -1;
	    goto bad2;
	}
    }

    /* set up the needed stuff for mutual auth */
    *faddr = sin;
    sin_len = sizeof (struct sockaddr_in);
    if (getsockname(s, (struct sockaddr *)laddr, &sin_len) < 0) {
	perror("getsockname");
	status = -1;
	goto bad2;
    }

    if ((status = krb_sendauth(authopts, s, ticket, service, *ahost,
			       realm, (unsigned long) getpid(), msg_data,
			       cred, schedule,
			       laddr,
			       faddr,
			       "KCMDV0.1")) != KSUCCESS) {
	fprintf(stderr, "krb_sendauth failed: %s\n", krb_get_err_text(status));
	status = -1;
	goto bad2;
    }
    (void) write(s, remuser, strlen(remuser)+1);
    (void) write(s, cmd, strlen(cmd)+1);

reread:
    if ((rc=read(s, &c, 1)) != 1) {
	if (rc==-1) {
	    perror(*ahost);
	} else {
	    fprintf(stderr,"rcmd: bad connection with remote host\n");
	}
	status = -1;
	goto bad2;
    }
    if (c != 0) {
	/* If rlogind was compiled on SunOS4, and it somehow
	   got the shared library version numbers wrong, it
	   may give an ld.so warning about an old version of a
	   shared library.  Just ignore any such warning.
	   Note that the warning is a characteristic of the
	   server; we may not ourselves be running under
	   SunOS4.  */
	if (c == 'l') {
	    char *check = "d.so: warning:";
	    char *p;
	    char cc;

	    p = check;
	    while (read(s, &c, 1) == 1) {
		if (*p == '\0') {
		    if (c == '\n')
			break;
		} else {
		    if (c != *p)
			break;
		    ++p;
		}
	    }

	    if (*p == '\0')
		goto reread;

	    cc = 'l';
	    (void) write(2, &cc, 1);
	    if (p != check)
		(void) write(2, check, p - check);
	}

	(void) write(2, &c, 1);
	while (read(s, &c, 1) == 1) {
	    (void) write(2, &c, 1);
	    if (c == '\n')
		break;
	}
	status = -1;
	goto bad2;
    }
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
    sigsetmask(oldmask);
#endif
    *sock = s;
    return (KSUCCESS);
 bad2:
    if (lport)
	(void) close(*fd2p);
 bad:
    (void) close(s);
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, &oldmask, (sigset_t*)0);
#else
    sigsetmask(oldmask);
#endif
    return (status);
}
#endif /* KRB5_KRB4_COMPAT */



getport(alport)
     int *alport;
{
    struct sockaddr_in sin;
    int s;
    int len = sizeof(sin);
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
	return (-1);

    memset((char *) &sin, 0,sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0) {
	if (alport) {
	    if (getsockname(s, (struct sockaddr *)&sin, &len) < 0) {
		(void) close(s);
		return -1;
	    } else {
		*alport = ntohs(sin.sin_port);
	    }
	}
	return s;
    }

    (void) close(s);
    return -1;
}

void rcmd_stream_init_normal()
{
    input = read;
    output = twrite;
}

void rcmd_stream_init_krb5(in_keyblock, encrypt_flag, lencheck)
     krb5_keyblock *in_keyblock;
     int encrypt_flag;
     int lencheck;
{
    krb5_error_code status;
    size_t blocksize;

    if (!encrypt_flag) {
	rcmd_stream_init_normal();
	return;
    }
    desinbuf.data = des_inbuf;
    desoutbuf.data = des_outpkt+4;	/* Set up des buffers */
    keyblock = in_keyblock;

    do_lencheck = lencheck;
    input = v5_des_read;
    output = v5_des_write;

    if (status = krb5_c_block_size(bsd_context, keyblock->enctype,
				   &blocksize)) {
	/* XXX what do I do? */
	abort();
    }

    encivec.length = blocksize;

    if ((encivec.data = malloc(encivec.length)) == NULL) {
	/* XXX what do I do? */
	abort();
    }

    /* is there a better way to initialize this? */
    memset(encivec.data, '\0', blocksize);
}

#ifdef KRB5_KRB4_COMPAT
void rcmd_stream_init_krb4(session, encrypt_flag, lencheck, justify)
     C_Block session;
     int encrypt_flag;
     int lencheck;
     int justify;
{
    if (!encrypt_flag) {
	rcmd_stream_init_normal();
	return;
    }
    do_lencheck = lencheck;
    right_justify = justify;
    input = v4_des_read;
    output = v4_des_write;
    memcpy(v4_session, session, sizeof(v4_session));
}
#endif

int rcmd_stream_read(fd, buf, len)
     int fd;
     register char *buf;
     int len;
{
    return (*input)(fd, buf, len);
}

int rcmd_stream_write(fd, buf, len)
     int fd;
     register char *buf;
     int len;
{
    return (*output)(fd, buf, len);
}

/* Because of rcp lossage, translate fd 0 to 1 when writing. */
static int twrite(fd, buf, len)
     int fd;
     char *buf;
     int len;
{
    return write((fd == 0) ? 1 : fd, buf, len);
}

static int v5_des_read(fd, buf, len)
     int fd;
     char *buf;
     int len;
{
    int nreturned = 0;
    size_t net_len,rd_len;
    int cc;
    unsigned char c;
    krb5_error_code ret;
    krb5_data plain;
    krb5_enc_data cipher;
    
    if (nstored >= len) {
	memcpy(buf, store_ptr, len);
	store_ptr += len;
	nstored -= len;
	return(len);
    } else if (nstored) {
	memcpy(buf, store_ptr, nstored);
	nreturned += nstored;
	buf += nstored;
	len -= nstored;
	nstored = 0;
    }

    /* See the comment in v4_des_read. */
    while (1) {
	cc = krb5_net_read(bsd_context, fd, &c, 1);
	/* we should check for non-blocking here, but we'd have
	   to make it save partial reads as well. */
	if (cc <= 0) return cc; /* read error */
	if (cc == 1) {
	    if (c == 0 || !do_lencheck) break;
	}
    }

    rd_len = c;
    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
    rd_len = (rd_len << 8) | c;
    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
    rd_len = (rd_len << 8) | c;
    if ((cc = krb5_net_read(bsd_context, fd, &c, 1)) != 1) return 0;
    rd_len = (rd_len << 8) | c;

    if (ret = krb5_c_encrypt_length(bsd_context, keyblock->enctype,
				  rd_len, &net_len)) {
	errno = ret;
	return(-1);
    }

    if ((net_len <= 0) || (net_len > sizeof(des_inbuf))) {
	/* preposterous length, probably out of sync */
	errno = EIO;
	return(-1);
    }
    if ((cc = krb5_net_read(bsd_context, fd, desinbuf.data, net_len)) != net_len) {
	/* probably out of sync */
	errno = EIO;
	return(-1);
    }

    cipher.enctype = ENCTYPE_UNKNOWN;
    cipher.ciphertext.length = net_len;
    cipher.ciphertext.data = desinbuf.data;
    plain.length = sizeof(storage);
    plain.data = storage;

    /* decrypt info */
    if (krb5_c_decrypt(bsd_context, keyblock, KCMD_KEYUSAGE, &encivec,
		       &cipher, &plain)) {
	/* probably out of sync */
	errno = EIO;
	return(-1);
    }
    store_ptr = storage;
    nstored = rd_len;
    if (nstored > len) {
	memcpy(buf, store_ptr, len);
	nreturned += len;
	store_ptr += len;
	nstored -= len;
    } else {
	memcpy(buf, store_ptr, nstored);
	nreturned += nstored;
	nstored = 0;
    }

    return(nreturned);
}



static int v5_des_write(fd, buf, len)
     int fd;
     char *buf;
     int len;
{
    unsigned char *len_buf = (unsigned char *) des_outpkt;
    krb5_data plain;
    krb5_enc_data cipher;

    plain.data = buf;
    plain.length = len;

    cipher.ciphertext.length = sizeof(des_outpkt)-4;
    cipher.ciphertext.data = desoutbuf.data;

    if (krb5_c_encrypt(bsd_context, keyblock, KCMD_KEYUSAGE, &encivec,
		       &plain, &cipher)) {
	errno = EIO;
	return(-1);
    }

    desoutbuf.length = cipher.ciphertext.length;

    len_buf[0] = (len & 0xff000000) >> 24;
    len_buf[1] = (len & 0xff0000) >> 16;
    len_buf[2] = (len & 0xff00) >> 8;
    len_buf[3] = (len & 0xff);

    if (write(fd, des_outpkt,desoutbuf.length+4) != desoutbuf.length+4){
	errno = EIO;
	return(-1);
    }

    else return(len);
}



#ifdef KRB5_KRB4_COMPAT

static int
v4_des_read(fd, buf, len)
int fd;
char *buf;
int len;
{
	int nreturned = 0;
	krb5_ui_4 net_len, rd_len;
	int cc;
	unsigned char c;

	if (nstored >= len) {
		memcpy(buf, store_ptr, len);
		store_ptr += len;
		nstored -= len;
		return(len);
	} else if (nstored) {
		memcpy(buf, store_ptr, nstored);
		nreturned += nstored;
		buf += nstored;
		len -= nstored;
		nstored = 0;
	}

	/* We're fetching the length which is MSB first, and the MSB
	   has to be zero unless the client is sending more than 2^24
	   (16M) bytes in a single write (which is why this code is used
	   in rlogin but not rcp or rsh.) The only reasons we'd get
	   something other than zero are:
		-- corruption of the tcp stream (which will show up when
		   everything else is out of sync too)
		-- un-caught Berkeley-style "pseudo out-of-band data" which
		   happens any time the user hits ^C twice.
	   The latter is *very* common, as shown by an 'rlogin -x -d' 
	   using the CNS V4 rlogin.         Mark EIchin 1/95
	   */
	while (1) {
	    cc = krb_net_read(fd, &c, 1);
	    if (cc <= 0) return cc; /* read error */
	    if (cc == 1) {
		if (c == 0 || !do_lencheck) break;
	    }
	}

	net_len = c;
	if ((cc = krb_net_read(fd, &c, 1)) != 1) return 0;
	net_len = (net_len << 8) | c;
	if ((cc = krb_net_read(fd, &c, 1)) != 1) return 0;
	net_len = (net_len << 8) | c;
	if ((cc = krb_net_read(fd, &c, 1)) != 1) return 0;
	net_len = (net_len << 8) | c;

	/* Note: net_len is unsigned */
	if (net_len > sizeof(des_inbuf)) {
		errno = EIO;
		return(-1);
	}
	/* the writer tells us how much real data we are getting, but
	   we need to read the pad bytes (8-byte boundary) */
	rd_len = roundup(net_len, 8);
	if ((cc = krb_net_read(fd, des_inbuf, rd_len)) != rd_len) {
		errno = EIO;
		return(-1);
	}
	(void) pcbc_encrypt(des_inbuf,
			    storage,
			    (net_len < 8) ? 8 : net_len,
			    v4_schedule,
			    v4_session,
			    DECRYPT);
	/* 
	 * when the cleartext block is < 8 bytes, it is "right-justified"
	 * in the block, so we need to adjust the pointer to the data
	 */
	if (net_len < 8 && right_justify)
		store_ptr = storage + 8 - net_len;
	else
		store_ptr = storage;
	nstored = net_len;
	if (nstored > len) {
		memcpy(buf, store_ptr, len);
		nreturned += len;
		store_ptr += len;
		nstored -= len;
	} else {
		memcpy(buf, store_ptr, nstored);
		nreturned += nstored;
		nstored = 0;
	}
	
	return(nreturned);
}

static int
v4_des_write(fd, buf, len)
int fd;
char *buf;
int len;
{
	static char garbage_buf[8];
	unsigned char *len_buf = (unsigned char *) des_outpkt;

	/* 
	 * pcbc_encrypt outputs in 8-byte (64 bit) increments
	 *
	 * it zero-fills the cleartext to 8-byte padding,
	 * so if we have cleartext of < 8 bytes, we want
	 * to insert random garbage before it so that the ciphertext
	 * differs for each transmission of the same cleartext.
	 * if len < 8 - sizeof(long), sizeof(long) bytes of random
	 * garbage should be sufficient; leave the rest as-is in the buffer.
	 * if len > 8 - sizeof(long), just garbage fill the rest.
	 */

#ifdef min
#undef min
#endif
#define min(a,b) ((a < b) ? a : b)

	if (len < 8 && right_justify) {
		krb5_random_confounder(8 - len, garbage_buf);
		/* this "right-justifies" the data in the buffer */
		(void) memcpy(garbage_buf + 8 - len, buf, len);
	}
	(void) pcbc_encrypt((len < 8) ? garbage_buf : buf,
			    des_outpkt+4,
			    (len < 8) ? 8 : len,
			    v4_schedule,
			    v4_session,
			    ENCRYPT);

	/* tell the other end the real amount, but send an 8-byte padded
	   packet */
	len_buf[0] = (len & 0xff000000) >> 24;
	len_buf[1] = (len & 0xff0000) >> 16;
	len_buf[2] = (len & 0xff00) >> 8;
	len_buf[3] = (len & 0xff);
	if (write(fd, des_outpkt, roundup(len,8)+4) != roundup(len,8)+4) {
		errno = EIO;
		return(-1);
	}
	return(len);
}

#endif /* KRB5_KRB4_COMPAT */

#ifndef HAVE_STRSAVE
/* Strsave was a routine in the version 4 krb library: we put it here
   for compatablilty with version 5 krb library, since kcmd.o is linked
   into all programs. */

char *
  strsave(sp)
char *sp;
{
    register char *ret;
    
    if((ret = (char *) malloc((unsigned) strlen(sp)+1)) == NULL) {
	fprintf(stderr, "no memory for saving args\n");
	exit(1);
    }
    (void) strcpy(ret,sp);
    return(ret);
}

#endif
