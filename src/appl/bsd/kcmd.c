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
#ifdef _AIX
#include <sys/select.h>
#endif

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


#define START_PORT      5120     /* arbitrary */
char *default_service = "host";

#define KCMD_KEYUSAGE	1026 /* Key usage used   with 3des or any old-protocol enctype*/
/* New protocol enctypes that use cipher state have keyusage defined later*/

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE int
#endif

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

/* XXX Overloaded: use_ivecs!=0 -> new protocol, inband signalling, etc.  */
static int use_ivecs;
static krb5_keyusage enc_keyusage_i[2], enc_keyusage_o[2];
static krb5_data encivec_i[2], encivec_o[2];

static krb5_keyblock *keyblock;		 /* key for encrypt/decrypt */
static int (*input)(int, char *, size_t, int);
static int (*output)(int, char *, size_t, int);
static char storage[2*RCMD_BUFSIZ];	 /* storage for the decryption */
static size_t nstored = 0;
static char *store_ptr = storage;
static int twrite(int, char *, size_t, int);
static int v5_des_read(int, char *, size_t, int), 
    v5_des_write(int, char *, size_t, int);
#ifdef KRB5_KRB4_COMPAT
static int v4_des_read(int, char *, size_t, int), 
    v4_des_write(int, char *, size_t, int);
static C_Block v4_session;
static int right_justify;
#endif
static int do_lencheck;

#ifdef KRB5_KRB4_COMPAT
extern int
krb_sendauth(long options, int fd, KTEXT ticket,
	     char *service, char *inst, char *realm,
	     unsigned KRB4_32 checksum,
	     MSG_DAT *msg_data,
	     CREDENTIALS *cred,
	     Key_schedule schedule,
	     struct sockaddr_in *laddr,
	     struct sockaddr_in *faddr,
	     char *version);
#endif

#ifdef POSIX_SIGNALS
typedef sigset_t masktype;
#else
typedef sigmasktype masktype;
#endif

static void
block_urgent (masktype *oldmask)
{
#ifdef POSIX_SIGNALS
    sigset_t urgmask;

    sigemptyset(&urgmask);
    sigaddset(&urgmask, SIGURG);
    sigprocmask(SIG_BLOCK, &urgmask, oldmask);
#else
    *oldmask = sigblock(sigmask(SIGURG));
#endif /* POSIX_SIGNALS */
}

static void
restore_sigs (masktype *oldmask)
{
#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, oldmask, (sigset_t*)0);
#else
    sigsetmask(*oldmask);
#endif /* POSIX_SIGNALS */
}

static int
kcmd_connect (int *sp, int *addrfamilyp, struct sockaddr_in *sockinp,
	      char *hname, char **host_save, unsigned int rport, int *lportp,
	      struct sockaddr_in *laddrp)
{
    int s, aierr;
    struct addrinfo *ap, *ap2, aihints;
    char rport_buf[10];
    GETSOCKNAME_ARG3_TYPE  sin_len;

    sprintf(rport_buf, "%d", ntohs(rport));
    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_socktype = SOCK_STREAM;
    aihints.ai_flags = AI_CANONNAME;
    aihints.ai_family = *addrfamilyp;
    aierr = getaddrinfo(hname, rport_buf, &aihints, &ap);
    if (aierr) {
	const char *msg;
	/* We want to customize some messages.  */
	switch (aierr) {
	case EAI_NONAME:
	    msg = "host unknown";
	    break;
	default:
	    fprintf(stderr, "foo\n");
	    msg = gai_strerror(aierr);
	    break;
	}
	fprintf(stderr, "%s: %s\n", hname, msg);
	return -1;
    }
    if (ap == 0) {
	fprintf(stderr, "%s: no addresses?\n", hname);
	return -1;
    }

    *host_save = strdup(ap->ai_canonname ? ap->ai_canonname : hname);

    for (ap2 = ap; ap; ap = ap->ai_next) {
	char hostbuf[NI_MAXHOST];
	int oerrno;
	int af = ap->ai_family;

	for (;;) {
	    s = getport(lportp, &af);
	    if (s < 0) {
		if (errno == EAGAIN)
		    fprintf(stderr, "socket: All ports in use\n");
		else
		    perror("kcmd: socket");
		return -1;
	    }
	    if (connect(s, ap->ai_addr, ap->ai_addrlen) >= 0)
		goto connected;
	    (void) close(s);
	    if (errno != EADDRINUSE)
		break;
	    if (lportp)
		(*lportp)--;
	}

	oerrno = errno;
	aierr = getnameinfo(ap->ai_addr, ap->ai_addrlen,
			    hostbuf, sizeof(hostbuf), 0, 0, NI_NUMERICHOST);
	if (aierr)
	    fprintf(stderr, "connect to <error formatting address: %s>: ",
		    gai_strerror (aierr));
	else
	    fprintf(stderr, "connect to address %s: ", hostbuf);
	errno = oerrno;
	perror(0);

	if (ap->ai_next)
	    fprintf(stderr, "Trying next address...\n");
    }
    freeaddrinfo(ap2);
    return -1;

connected:
    sin_len = sizeof(struct sockaddr_in);
    if (getsockname(s, (struct sockaddr *)laddrp, &sin_len) < 0) {
	perror("getsockname");
	close(s);
	return -1;
    }

    *sp = s;
    *sockinp = *(struct sockaddr_in *) ap->ai_addr;
    freeaddrinfo(ap2);
    return 0;
}

static int
setup_secondary_channel (int s, int *fd2p, int *lportp, int *addrfamilyp,
			 struct sockaddr_in *fromp, int anyport)
{
    if (fd2p == 0) {
    	write(s, "", 1);
    	*lportp = 0;
    } else {
    	char num[8];
    	int len = sizeof (*fromp);
	size_t slen;
    	int s2 = getport(lportp, addrfamilyp), s3;
	fd_set rfds, xfds;
	struct timeval waitlen;
	int n;

	*fd2p = -1;
	if (s2 < 0)
	    return -1;
	FD_ZERO(&rfds);
	FD_ZERO(&xfds);
	FD_SET(s, &rfds);
	FD_SET(s, &xfds);
	listen(s2, 1);
	FD_SET(s2, &rfds);
    	(void) sprintf(num, "%d", *lportp);
	slen = strlen(num)+1;
    	if (write(s, num, slen) != slen) {
	    perror("write: setting up stderr");
	    (void) close(s2);
	    return -1;
    	}
	waitlen.tv_sec = 600;	/* long, but better than infinite */
	waitlen.tv_usec = 0;
	n = (s < s2) ? s2 : s;
	n = select(n+1, &rfds, 0, &xfds, &waitlen);
	if (n <= 0) {
	    /* timeout or error */
	    fprintf(stderr, "timeout in circuit setup\n");
	    close(s2);
	    *fd2p = -1;
	    return -1;
	} else {
	    if (FD_ISSET(s, &rfds) || FD_ISSET(s, &xfds)) {
		fprintf(stderr, "socket: protocol error or closed connection in circuit setup\n");
		close(s2);
		*fd2p = -1;
		return -1;
	    }
	    /* ready to accept a connection; yay! */
	}
    	s3 = accept(s2, (struct sockaddr *)fromp, &len);
    	(void) close(s2);
    	if (s3 < 0) {
	    perror("accept");
	    *lportp = 0;
	    return -1;
    	}
    	*fd2p = s3;
    	fromp->sin_port = ntohs(fromp->sin_port);
	/* This check adds nothing when using Kerberos.  */
    	if (! anyport &&
	    (fromp->sin_family != AF_INET ||
    	     fromp->sin_port >= IPPORT_RESERVED)) {
	    fprintf(stderr, "socket: protocol failure in circuit setup.\n");
	    close(s3);
	    *fd2p = -1;
	    return -1;
    	}
    }
    return 0;
}

int
kcmd(sock, ahost, rport, locuser, remuser, cmd, fd2p, service, realm,
     cred, seqno, server_seqno, laddr, faddr, authconp, authopts, anyport,
     suppress_err, protonump)
     int *sock;
     char **ahost;
     u_short rport;
     char *locuser, *remuser, *cmd;
     int *fd2p;
     char *service;
     char *realm;
     krb5_creds **cred; /* output only */
     krb5_int32 *seqno;
     krb5_int32 *server_seqno;
     struct sockaddr_in *laddr, *faddr;
     krb5_auth_context *authconp;
     krb5_flags authopts;
     int anyport;
     int suppress_err;		/* Don't print if authentication fails */
     enum kcmd_proto *protonump;
{
    int s;
    masktype oldmask;
    struct sockaddr_in sockin, from, local_laddr;
    krb5_creds *get_cred = 0, *ret_cred = 0;
    char c;
    int lport;
    int rc;
    char *host_save;
    krb5_error_code status;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_error	*error = 0;
    krb5_ccache cc;
    krb5_data outbuf;
    krb5_flags options = authopts;
    krb5_auth_context auth_context = NULL;
    char *cksumbuf;
    krb5_data cksumdat;
    char *kcmd_version;
    enum kcmd_proto protonum = *protonump;
    int addrfamily = /* AF_INET */0;

    if ((cksumbuf = malloc(strlen(cmd)+strlen(remuser)+64)) == 0 ) {
	fprintf(stderr, "Unable to allocate memory for checksum buffer.\n");
	return(-1);
    }
    sprintf(cksumbuf, "%u:", ntohs(rport));
    strcat(cksumbuf, cmd);
    strcat(cksumbuf, remuser);
    cksumdat.data = cksumbuf;
    cksumdat.length = strlen(cksumbuf);
	
    block_urgent(&oldmask);
    
    if (!laddr) laddr = &local_laddr;
    if (kcmd_connect(&s, &addrfamily, &sockin, *ahost, &host_save, rport, 0, laddr) == -1) {
	restore_sigs(&oldmask);
	return -1;
    }
    *ahost = host_save;
    /* If no service is given set to the default service */
    if (!service) service = default_service;
    
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
        status = krb5_set_principal_realm(bsd_context, get_cred->server,
					  realm);
	if (status) {
	  fprintf(stderr, "kcmd: krb5_set_principal_realm failed %s\n", 
		  error_message(status));
	  return(-1);
	}
    }
    status = setup_secondary_channel(s, fd2p, &lport, &addrfamily, &from,
				     anyport);
    if (status)
	goto bad;

    if (faddr)
	*faddr = sockin;

    status = krb5_cc_default(bsd_context, &cc);
    if (status)
    	goto bad2;

    status = krb5_cc_get_principal(bsd_context, cc, &get_cred->client);
    if (status) {
    	(void) krb5_cc_close(bsd_context, cc);
    	goto bad2;
    }

    /* Get ticket from credentials cache or kdc */
    status = krb5_get_credentials(bsd_context, 0, cc, get_cred, &ret_cred);
    krb5_free_creds(bsd_context, get_cred);
    (void) krb5_cc_close(bsd_context, cc);
    if (status) {
	fprintf (stderr, "error getting credentials: %s\n",
		 error_message (status));
	goto bad2;
    }

    /* Reset internal flags; these should not be sent. */
    authopts &= (~OPTS_FORWARD_CREDS);
    authopts &= (~OPTS_FORWARDABLE_CREDS);

    if (krb5_auth_con_init(bsd_context, &auth_context)) 
	goto bad2;

    if (krb5_auth_con_setflags(bsd_context, auth_context, 
			       KRB5_AUTH_CONTEXT_RET_TIME))
	goto bad2;

    /* Only need local address for mk_cred() to send to krlogind */
    status = krb5_auth_con_genaddrs(bsd_context, auth_context, s,
				   KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR);
    if (status)
	goto bad2;

    if (protonum == KCMD_PROTOCOL_COMPAT_HACK) {
	krb5_boolean is_des;
	status = krb5_c_enctype_compare (bsd_context, ENCTYPE_DES_CBC_CRC,
					 ret_cred->keyblock.enctype, &is_des);
	if (status)
	    goto bad2;
	protonum = is_des ? KCMD_OLD_PROTOCOL : KCMD_NEW_PROTOCOL;
    }

    switch (protonum) {
    case KCMD_NEW_PROTOCOL:
	authopts |= AP_OPTS_USE_SUBKEY;
	kcmd_version = "KCMDV0.2";
	break;
    case KCMD_OLD_PROTOCOL:
	kcmd_version = "KCMDV0.1";
	break;
    default:
	status = EINVAL;
	goto bad2;
    }

    /* Call Kerberos library routine to obtain an authenticator,
       pass it over the socket to the server, and obtain mutual
       authentication.  */
    status = krb5_sendauth(bsd_context, &auth_context, (krb5_pointer) &s,
			   kcmd_version, ret_cred->client, ret_cred->server,
			   authopts, &cksumdat, ret_cred, 0,
			   &error, &rep_ret, NULL);
    free(cksumbuf);
    if (status) {
	if (!suppress_err)
	    fprintf(stderr, "Couldn't authenticate to server: %s\n",
		    error_message(status));
	if (error) {
	    if (!suppress_err) {
		fprintf(stderr, "Server returned error code %d (%s)\n",
			error->error,
			error_message(ERROR_TABLE_BASE_krb5 + 
				      (int) error->error));
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
	status = krb5_fwd_tgt_creds(bsd_context, auth_context,
				    host_save,
				    ret_cred->client, ret_cred->server,
				    0, options & OPTS_FORWARDABLE_CREDS,
				    &outbuf);
	if (status) {
	    fprintf(stderr, "kcmd: Error getting forwarded creds\n");
	    goto bad2;
	}

	/* Send forwarded credentials */
	status = krb5_write_message(bsd_context, (krb5_pointer)&s, &outbuf);
	if (status)
	  goto bad2;
    }
    else { /* Dummy write to signal no forwarding */
	outbuf.length = 0;
	status = krb5_write_message(bsd_context, (krb5_pointer)&s, &outbuf);
	if (status)
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
    restore_sigs(&oldmask);
    *sock = s;
    *protonump = protonum;
    
    /* pass back credentials if wanted */
    if (cred) krb5_copy_creds(bsd_context, ret_cred, cred);
    krb5_free_creds(bsd_context, ret_cred);
    if (authconp)
	*authconp = auth_context;
    
    return (0);
  bad2:
    if (lport)
      (void) close(*fd2p);
  bad:
    (void) close(s);
    restore_sigs(&oldmask);
    if (ret_cred)
      krb5_free_creds(bsd_context, ret_cred);
    return (status);
}



#ifdef KRB5_KRB4_COMPAT
int
k4cmd(sock, ahost, rport, locuser, remuser, cmd, fd2p, ticket, service, realm,
      cred, schedule, msg_data, laddr, faddr, authopts, anyport)
     int *sock;
     char **ahost;
     unsigned int rport;
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
    int s;
    masktype oldmask;
    struct sockaddr_in sockin, from;
    char c;
    int lport = START_PORT;
    int rc;
    char *host_save;
    int status;
    int addrfamily = AF_INET;

    block_urgent(&oldmask);
    if (kcmd_connect (&s, &addrfamily, &sockin, *ahost, &host_save, rport, &lport, laddr) == -1) {
	restore_sigs(&oldmask);
	return -1;
    }
    *ahost = host_save;
    /* If realm is null, look up from table */
    if ((realm == NULL) || (realm[0] == '\0')) {
	realm = krb_realmofhost(host_save);
    }
    lport--;
    status = setup_secondary_channel(s, fd2p, &lport, &addrfamily, &from,
				     anyport);
    if (status)
	goto bad;

    /* set up the needed stuff for mutual auth */
    *faddr = sockin;

    status = krb_sendauth(authopts, s, ticket, service, *ahost,
			  realm, (unsigned long) getpid(), msg_data,
			  cred, schedule, laddr, faddr, "KCMDV0.1");
    if (status != KSUCCESS) {
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
		(void) write(2, check, (unsigned) (p - check));
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
    restore_sigs(&oldmask);
    *sock = s;
    return (KSUCCESS);
 bad2:
    if (lport)
	(void) close(*fd2p);
 bad:
    (void) close(s);
    restore_sigs(&oldmask);
    return (status);
}
#endif /* KRB5_KRB4_COMPAT */


static int
setup_socket (struct sockaddr *sa, GETSOCKNAME_ARG3_TYPE len)
{
    int s;

    s = socket(sa->sa_family, SOCK_STREAM, 0);
    if (s < 0)
	return -1;

    if (bind(s, sa, len) < 0)
	return -1;
    if (getsockname(s, sa, &len) < 0) {
	close(s);
	return -1;
    }
    return s;
}


int
getport(alport, family)
    int *alport, *family;
{
    int s;

    if (*family == 0) {
#ifdef KRB5_USE_INET6
	*family = AF_INET6;
	s = getport (alport, family);
	if (s >= 0)
	    return s;
#endif
	*family = AF_INET;
    }

#ifdef KRB5_USE_INET6
    if (*family == AF_INET6) {
	struct sockaddr_in6 sockin6;

	memset(&sockin6, 0, sizeof(sockin6));
	sockin6.sin6_family = AF_INET6;
	sockin6.sin6_addr = in6addr_any;

	s = setup_socket((struct sockaddr *)&sockin6, sizeof (sockin6));
	if (s >= 0 && alport)
	    *alport = ntohs(sockin6.sin6_port);
	return s;
    }
#endif

    if (*family == AF_INET) {
	struct sockaddr_in sockin;

	memset(&sockin, 0, sizeof(sockin));
	sockin.sin_family = AF_INET;
	sockin.sin_addr.s_addr = INADDR_ANY;

	s = setup_socket((struct sockaddr *)&sockin, sizeof (sockin));
	if (s >= 0 && alport)
	    *alport = ntohs(sockin.sin_port);
	return s;
    }

    return -1;
}

static int
normal_read (int fd, char *buf, size_t len, int secondary)
{
    return read (fd, buf, len);
}

void rcmd_stream_init_normal()
{
    input = normal_read;
    output = twrite;
}

void rcmd_stream_init_krb5(in_keyblock, encrypt_flag, lencheck, am_client,
			   protonum)
     krb5_keyblock *in_keyblock;
     int encrypt_flag;
     int lencheck;
     int am_client;
     enum kcmd_proto protonum;
{
    krb5_error_code status;
    size_t blocksize;
    int i;
    krb5_error_code ret;

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
    enc_keyusage_i[0] = KCMD_KEYUSAGE;
    enc_keyusage_i[1] = KCMD_KEYUSAGE;
    enc_keyusage_o[0] = KCMD_KEYUSAGE;
    enc_keyusage_o[1] = KCMD_KEYUSAGE;

    if (protonum == KCMD_OLD_PROTOCOL) {
	use_ivecs = 0;
	return;
    }

    use_ivecs = 1;
    switch (in_keyblock->enctype) {
      /* 
       * For the DES-based enctypes and the 3DES enctype we  want to use
       *  a non-zero  IV because that's what we did.  In the future we
       * use different keyusage for each channel and direction and a fresh
       * cipher state
       */
    case ENCTYPE_DES_CBC_CRC:
    case ENCTYPE_DES_CBC_MD4:
    case ENCTYPE_DES_CBC_MD5:
    case ENCTYPE_DES3_CBC_SHA1:
      
      status = krb5_c_block_size(bsd_context, keyblock->enctype,
				 &blocksize);
      if (status) {
	/* XXX what do I do? */
	abort();
      }

      encivec_i[0].length = encivec_i[1].length = encivec_o[0].length
	= encivec_o[1].length = blocksize;

      if ((encivec_i[0].data = malloc(encivec_i[0].length * 4)) == NULL) {
	/* XXX what do I do? */
	abort();
      }
      encivec_i[1].data = encivec_i[0].data + encivec_i[0].length;
      encivec_o[0].data = encivec_i[1].data + encivec_i[0].length;
      encivec_o[1].data = encivec_o[0].data + encivec_i[0].length;

    /* is there a better way to initialize this? */
      memset(encivec_i[0].data, am_client, blocksize);
      memset(encivec_o[0].data, 1 - am_client, blocksize);
      memset(encivec_i[1].data, 2 | am_client, blocksize);
      memset(encivec_o[1].data, 2 | (1 - am_client), blocksize);
      break;
    default:
      if (am_client) {
	enc_keyusage_i[0] = 1028;
	enc_keyusage_i[1] = 1030;
	enc_keyusage_o[0] = 1032;
	enc_keyusage_o[1] = 1034;
      } else { /*am_client*/
	enc_keyusage_i[0] = 1032;
	enc_keyusage_i[1] = 1034;
	enc_keyusage_o[0] = 1028;
	enc_keyusage_o[1] = 1030;
      }
      for (i = 0; i < 2; i++) {
	ret = krb5_c_init_state (bsd_context, in_keyblock, enc_keyusage_i[i],
				 &encivec_i[i]);
	if (ret)
	  goto fail;
	ret = krb5_c_init_state (bsd_context, in_keyblock, enc_keyusage_o[i],
				 &encivec_o[i]);
	if (ret)
	  goto fail;
      }
      break;
    }
    return;
 fail:
    com_err ("kcmd", ret, "Initializing cipher state");
    abort();
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

int rcmd_stream_read(fd, buf, len, sec)
     int fd;
     register char *buf;
     size_t len;
     int sec;
{
    return (*input)(fd, buf, len, sec);
}

int rcmd_stream_write(fd, buf, len, sec)
     int fd;
     register char *buf;
     size_t len;
     int sec;
{
    return (*output)(fd, buf, len, sec);
}

/* Because of rcp lossage, translate fd 0 to 1 when writing. */
static int twrite(fd, buf, len, secondary)
     int fd;
     char *buf;
     size_t len;
     int secondary;
{
    return write((fd == 0) ? 1 : fd, buf, len);
}

static int v5_des_read(fd, buf, len, secondary)
     int fd;
     char *buf;
     size_t len;
     int secondary;
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

    ret = krb5_c_encrypt_length(bsd_context, keyblock->enctype,
				use_ivecs ? rd_len + 4 : rd_len,
				&net_len);
    if (ret) {
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
    ret = krb5_c_decrypt(bsd_context, keyblock, enc_keyusage_i[secondary],
			 use_ivecs ? encivec_i + secondary : 0,
			 &cipher, &plain);
    if (ret) {
	/* probably out of sync */
	errno = EIO;
	return(-1);
    }
    store_ptr = storage;
    nstored = rd_len;
    if (use_ivecs) {
	int rd_len2;
	rd_len2 = storage[0] & 0xff;
	rd_len2 <<= 8; rd_len2 |= storage[1] & 0xff;
	rd_len2 <<= 8; rd_len2 |= storage[2] & 0xff;
	rd_len2 <<= 8; rd_len2 |= storage[3] & 0xff;
	if (rd_len2 != rd_len) {
	    /* cleartext length trashed? */
	    errno = EIO;
	    return -1;
	}
	store_ptr += 4;
    }
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



static int v5_des_write(fd, buf, len, secondary)
     int fd;
     char *buf;
     size_t len;
     int secondary;
{
    krb5_data plain;
    krb5_enc_data cipher;
    char tmpbuf[2*RCMD_BUFSIZ+8];
    unsigned char *len_buf = (unsigned char *) tmpbuf;

    if (use_ivecs) {
	unsigned char *lenbuf2 = (unsigned char *) tmpbuf;
	if (len + 4 > sizeof(tmpbuf))
	    abort ();
	lenbuf2[0] = (len & 0xff000000) >> 24;
	lenbuf2[1] = (len & 0xff0000) >> 16;
	lenbuf2[2] = (len & 0xff00) >> 8;
	lenbuf2[3] = (len & 0xff);
	memcpy (tmpbuf + 4, buf, len);

	plain.data = tmpbuf;
	plain.length = len + 4;
    } else {
	plain.data = buf;
	plain.length = len;
    }

    cipher.ciphertext.length = sizeof(des_outpkt)-4;
    cipher.ciphertext.data = desoutbuf.data;

    if (krb5_c_encrypt(bsd_context, keyblock, enc_keyusage_o[secondary],
		       use_ivecs ? encivec_o + secondary : 0,
		       &plain, &cipher)) {
	errno = EIO;
	return(-1);
    }

    desoutbuf.length = cipher.ciphertext.length;

    len_buf = (unsigned char *) des_outpkt;
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
v4_des_read(fd, buf, len, secondary)
int fd;
char *buf;
size_t len;
int secondary;
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
	(void) pcbc_encrypt((des_cblock *) des_inbuf,
			    (des_cblock *) storage,
			    (int) ((net_len < 8) ? 8 : net_len),
			    v4_schedule,
			    &v4_session,
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
v4_des_write(fd, buf, len, secondary)
int fd;
char *buf;
size_t len;
int secondary;
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

	if (len < 8) {
		if (right_justify) {
			krb5_random_confounder(8 - len, garbage_buf);
			/* this "right-justifies" the data in the buffer */
			(void) memcpy(garbage_buf + 8 - len, buf, len);
		} else {
			krb5_random_confounder(8 - len, garbage_buf + len);
			(void) memcpy(garbage_buf, buf, len);
		}
	}
	(void) pcbc_encrypt((des_cblock *) ((len < 8) ? garbage_buf : buf),
			    (des_cblock *) (des_outpkt+4),
			    (int) ((len < 8) ? 8 : len),
			    v4_schedule,
			    &v4_session,
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
    const char *sp;
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

/* Server side authentication, etc */

int princ_maps_to_lname(principal, luser)	
     krb5_principal principal;
     char *luser;
{
    char kuser[10];
    if (!(krb5_aname_to_localname(bsd_context, principal,
				  sizeof(kuser), kuser))
	&& (strcmp(kuser, luser) == 0)) {
	return 1;
    }
    return 0;
}

int default_realm(principal)
     krb5_principal principal;
{
    char *def_realm;
    unsigned int realm_length;
    int retval;
    
    realm_length = krb5_princ_realm(bsd_context, principal)->length;
    
    if ((retval = krb5_get_default_realm(bsd_context, &def_realm))) {
	return 0;
    }
    
    if ((realm_length != strlen(def_realm)) ||
	(memcmp(def_realm, krb5_princ_realm(bsd_context, principal)->data, 
		realm_length))) {
	free(def_realm);
	return 0;
    }	
    free(def_realm);
    return 1;
}

