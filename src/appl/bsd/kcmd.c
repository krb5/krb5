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
     
#include <netinet/in.h>
#include <netdb.h>
     
#include <errno.h>
#include "krb5.h"

#include "defines.h"


#define START_PORT      5120     /* arbitrary */
char *default_service = "host";

extern krb5_context bsd_context;


kcmd(sock, ahost, rport, locuser, remuser, cmd, fd2p, service, realm,
     cred, seqno, server_seqno, laddr, faddr, authopts, anyport)
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
    int lport = START_PORT;
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
        s = getport(&lport);
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
    	if (errno == EADDRINUSE) {
	    lport--;
	    continue;
    	}

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
	printf("Couldn't authenticate to server: %s\n", error_message(status));
	if (error) {
	    printf("Server returned error code %d (%s)\n", error->error,
		   error_message(ERROR_TABLE_BASE_krb5 + error->error));
	    if (error->text.length) {
		fprintf(stderr, "Error text sent from server: %s\n",
			error->text.data);
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



getport(alport)
     int *alport;
{
    struct sockaddr_in sin;
    int s;
    
    memset((char *) &sin, 0,sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
      return (-1);
    for (;;) {
	sin.sin_port = htons((u_short)*alport);
	if (bind(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0)
	  return (s);
	if (errno != EADDRINUSE) {
	    (void) close(s);
	    return (-1);
	}
	(*alport)--;
	if (*alport == IPPORT_RESERVED) {
	    (void) close(s);
	    errno = EAGAIN;		/* close */
	    return (-1);
	}
    }
}





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

