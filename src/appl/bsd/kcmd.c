/*
 *    $Source$
 *    $Id$
 */

#ifndef lint
static char *rcsid_kcmd_c =
  "$Id$";
#endif /* lint */
#define LIBC_SCCS

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

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "derived from @(#)rcmd.c	5.17 (Berkeley) 6/27/88";
#endif /* LIBC_SCCS and not lint */
     
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <sys/param.h>
#ifndef _TYPES_
#include <sys/types.h>
#define _TYPES_
#endif
     
     
#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif
#include <sys/file.h>
#include <sys/signal.h>
#ifndef sigmask
#define sigmask(m)    (1 << ((m)-1))
#endif
#include <sys/socket.h>
#include <sys/stat.h>
     
#include <netinet/in.h>
#include <netdb.h>
     
#include <errno.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include "defines.h"
     
#ifndef MAXHOSTNAMELEN 
#define MAXHOSTNAMELEN 64
#endif
     
extern	errno;

#define	START_PORT	5120	 /* arbitrary */
char *default_service = "host";

extern krb5_cksumtype krb5_kdc_req_sumtype;

kcmd(sock, ahost, rport, locuser, remuser, cmd, fd2p, service, realm,
     cred, seqno, server_seqno, laddr, faddr, authopts)
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
{
    int i, s, timo = 1, pid;
    long oldmask;
    struct sockaddr_in sin, from, local_laddr;
    krb5_creds *ret_cred = 0;
    char c;
    int lport = START_PORT;
    struct hostent *hp;
    int rc;
    char *host_save;
    krb5_error_code status;
    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_checksum send_cksum;
    char *tmpstr = 0;
    krb5_error	*error = 0;
    int sin_len;
    krb5_ccache cc;
    krb5_data outbuf;
    krb5_flags options = authopts;

    pid = getpid();
    hp = gethostbyname(*ahost);
    if (hp == 0) {
	fprintf(stderr, "%s: unknown host\n", *ahost);
	return (-1);
    }
    
    host_save = malloc(strlen(hp->h_name) + 1);
    if ( host_save == (char *) 0){
        fprintf(stderr,"kcmd: no memory\n");
        return(-1);
    }

    strcpy(host_save, hp->h_name);

    *ahost = host_save;
    
    /* If no service is given set to the default service */
    if (!service) service = default_service;
    
    sin_len = strlen(host_save) + strlen(service)
      + (realm ? strlen(realm): 0) + 3;
    if ( sin_len < 20 ) sin_len = 20;
    tmpstr = (char *) malloc(sin_len);
    if ( tmpstr == (char *) 0){
	fprintf(stderr,"kcmd: no memory\n");
	return(-1);
    }
    
    if (!(ret_cred = (krb5_creds *)calloc(1,sizeof(*ret_cred)))){
        fprintf(stderr,"kcmd: no memory\n");
        return(-1);
    }
    status = krb5_sname_to_principal(host_save,service,KRB5_NT_SRV_HST,
				     &ret_cred->server);
    if (status) {
	    fprintf(stderr, "kcmd: krb5_sname_to_principal failed: %s\n",
		    error_message(status));
	    return(-1);
    }

    if (realm && *realm) {
       char *copyrealm;
       krb5_data rdata;

       rdata.length = strlen(realm);
       rdata.data = (char *) malloc(rdata.length+1);
       strcpy(rdata.data, realm);
       
       /* XXX we should free the old realm first */
       krb5_princ_set_realm(ret_cred->server, &rdata);
   }
#ifdef sgi
    oldmask = sigignore(sigmask(SIGURG));
#else
    oldmask = sigblock(sigmask(SIGURG));
#endif
    
    for (;;) {
        s = getport(&lport);
    	if (s < 0) {
	    if (errno == EAGAIN)
	      fprintf(stderr, "socket: All ports in use\n");
	    else
	      perror("kcmd: socket");
#ifndef sgi
	    sigsetmask(oldmask);
#endif
	    if (tmpstr) krb5_xfree(tmpstr);
	    if (host_save) krb5_xfree(host_save);
	    krb5_free_creds(ret_cred);
	    return (-1);
    	}
#if defined (hpux) || defined (CRAY)  /*hpux does not handle async
    		 			io thus setown is disabled */
#else
    	fcntl(s, F_SETOWN, pid);
#endif /* hpux */
    	sin.sin_family = hp->h_addrtype;
    	memcpy((caddr_t)&sin.sin_addr,hp->h_addr, hp->h_length);
    	sin.sin_port = rport;
    	if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) >= 0)
	  break;
    	(void) close(s);
    	if (errno == EADDRINUSE) {
	    lport--;
	    continue;
    	}
	/*
	 * don't wait very long for Kerberos kcmd.
	 */
    	if (errno == ECONNREFUSED && timo <= 4) {
	    sleep(timo);
	    timo *= 2;
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
		   hp->h_length);
	    fprintf(stderr, "Trying %s...\n",
		    inet_ntoa(sin.sin_addr));
	    continue;
    	}
#endif /* !(defined(ultrix) || defined(sun)) */
    	perror(hp->h_name);
#ifndef sgi
    	sigsetmask(oldmask);
#endif
	if (tmpstr) krb5_xfree(tmpstr);
	if (host_save) krb5_xfree(host_save);
	krb5_free_creds(ret_cred);
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
    	if (from.sin_family != AF_INET ||
    	    from.sin_port >= IPPORT_RESERVED) {
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
    
    /* compute checksum, using CRC-32 */
    if (!(send_cksum.contents = (krb5_octet *)
          malloc(krb5_checksum_size(CKSUMTYPE_CRC32)))) {
        status = -1;
        goto bad2;
    }
    /* choose some random stuff to compute checksum from */
    sprintf(tmpstr,"%x %x",pid,pid);
    if (status = krb5_calculate_checksum(CKSUMTYPE_CRC32,
                                         tmpstr,
                                         strlen(tmpstr),
                                         0,
                                         0, /* if length is 0, crc-32 doesn't
                                               use the seed */
                                         &send_cksum)) 
      goto bad3;
    
    status = krb5_cc_default(&cc);
    if (status) goto bad3;

    status = krb5_cc_get_principal(cc, &ret_cred->client);
    if (status) goto bad3;

    /* Get ticket from credentials cache or kdc */
    status = krb5_get_credentials(0, cc, ret_cred);
    if (status) goto bad3;

    /* Reset internal flags; these should not be sent. */
    authopts &= (~OPTS_FORWARD_CREDS);
    authopts &= (~OPTS_FORWARDABLE_CREDS);

   /* call Kerberos library routine to obtain an authenticator,
       pass it over the socket to the server, and obtain mutual
       authentication. */
    status = krb5_sendauth((krb5_pointer) &s,
                           "KCMDV0.1", ret_cred->client, ret_cred->server,
			   authopts,
                           &send_cksum,
                           ret_cred,
                           0,		/* We have the credentials */
                           seqno,
                           0,           /* don't need a subsession key */
                           &error,		/* No error return */
                           &rep_ret);
    if (status) {
	printf("Couldn't authenticate to server: %s\n", error_message(status));
	if (error) {
	    printf("Server returned error code %d (%s)\n", error->error,
		   error_message(ERROR_TABLE_BASE_krb5 + error->error));
	    if (error->text.length) {
		fprintf(stderr, "Error text sent from server: %s\n",
			error->text.data);
	    }
	    krb5_free_error(error);
	    error = 0;
	}
    }	
    if (status) goto bad3;
    if (rep_ret && server_seqno) {
	*server_seqno = rep_ret->seq_number;
	krb5_free_ap_rep_enc_part(rep_ret);
    }
    
    (void) write(s, remuser, strlen(remuser)+1);
    (void) write(s, cmd, strlen(cmd)+1);
    (void) write(s, locuser, strlen(locuser)+1);
    
    if (options & OPTS_FORWARD_CREDS) {   /* Forward credentials */
	if (status = get_for_creds(ETYPE_DES_CBC_CRC,
				   krb5_kdc_req_sumtype,
				   hp->h_name,
				   ret_cred->client,
				   &ret_cred->keyblock,
				   /* Forwardable TGT? */
				   options & OPTS_FORWARDABLE_CREDS,
				   &outbuf)) {
	    fprintf(stderr, "kcmd: Error getting forwarded creds\n");
	    goto bad2;
	}
	
	/* Send forwarded credentials */
	if (status = krb5_write_message((krb5_pointer)&s, &outbuf))
	  goto bad3;
    }
    else { /* Dummy write to signal no forwarding */
	outbuf.length = 0;
	if (status = krb5_write_message((krb5_pointer)&s, &outbuf))
	  goto bad3;
    }

    if ((rc=read(s, &c, 1)) != 1) {
	if (rc==-1) {
	    perror(*ahost);
	} else {
	    fprintf(stderr,"kcmd: bad connection with remote host\n");
	}
	status = -1;
	goto bad3;
    }
    if (c != 0) {
	while (read(s, &c, 1) == 1) {
	    (void) write(2, &c, 1);
	    if (c == '\n')
	      break;
	}
	status = -1;
	goto bad3;
    }
#ifndef sgi
    sigsetmask(oldmask);
#endif
    *sock = s;
    if (tmpstr) krb5_xfree(tmpstr);
    if (host_save) krb5_xfree(host_save);
    
    /* pass back credentials if wanted */
    if (cred) krb5_copy_creds(ret_cred,cred);
    krb5_free_creds(ret_cred);
    
    return (0);
  bad3:
    free(send_cksum.contents);
  bad2:
    if (lport)
      (void) close(*fd2p);
  bad:
    (void) close(s);
#ifndef sgi
    sigsetmask(oldmask);
#endif
    if (tmpstr) krb5_xfree(tmpstr);
    if (host_save) krb5_xfree(host_save);
    if (ret_cred)
      krb5_free_creds(ret_cred);
    return (status);
}



getport(alport)
     int *alport;
{
    struct sockaddr_in sin;
    int s;
    
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



#if defined(sun)
/* The IMP  and ultrix do not like multiple defined routines 
   and since it does not have users with NFS filesystems 
   mounted, the ruserok on it's OS will work just fine. 
   However that is not the case with SUNS who's ruserok which 
   is provided with the OS has problems with it's seteuid
   ( which will eventually be traced no doubt to using
   setreuid(-1,pgid)).
   Therefore we provide a version of ruserok with fixes
   the seteuid problem....Drawback - it can only be used
   by a root process.*/

#ifndef convex
ruserok(rhost, superuser, ruser, luser)
     char *rhost;
     int superuser;
     char *ruser, *luser;
{
    FILE *hostf;
    char fhost[MAXHOSTNAMELEN];
    int first = 1;
    register char *sp, *p;
    int baselen = -1;
    int euid = -1;
    
    sp = rhost;
    p = fhost;
    while (*sp) {
	if (*sp == '.') {
	    if (baselen == -1)
	      baselen = sp - rhost;
	    *p++ = *sp++;
	} else {
	    *p++ = islower(*sp) ? toupper(*sp++) : *sp++;
	}
    }
    *p = '\0';
    hostf = superuser ? (FILE *)0 : fopen("/etc/hosts.equiv", "r");
  again:
    if (hostf) {
	if (!_validuser(hostf, fhost, luser, ruser, baselen)) {
	    (void) fclose(hostf);
	    if (euid != -1)
	      (void) setreuid ( 0,euid);
	    return(0);
	}
	(void) fclose(hostf);
    }
    if (first == 1) {
	struct stat sbuf;
	struct passwd *pwd;
	char pbuf[MAXPATHLEN];
	
	first = 0;
	if ((pwd = getpwnam(luser)) == NULL)
	  return(-1);
	/*
	 * Read .rhosts as the local user to avoid NFS mapping the 
	 * root uid to something that can't read .rhosts.
	 */
	euid = geteuid();
	if (euid != -1)
	  (void) setreuid ( 0,pwd->pw_uid);
	(void)strcpy(pbuf, pwd->pw_dir);
	(void)strcat(pbuf, "/.rhosts");
	if ((hostf = fopen(pbuf, "r")) == NULL){
	    if (euid != -1)
	      (void) setreuid ( 0,euid);
	    return(-1);
	}
	(void)fstat(fileno(hostf), &sbuf);
	if (sbuf.st_uid && sbuf.st_uid != pwd->pw_uid) {
	    fclose(hostf);
	    if (euid != -1)
	      (void) setreuid ( 0,euid);
	    return(-1);
	}
	goto again;
    }
    if (euid != -1)
      (void) setreuid ( 0,euid);
    return (-1);
}



_validuser(hostf, rhost, luser, ruser, baselen)
     char *rhost, *luser, *ruser;
     FILE *hostf;
     int baselen;
{
    char *user;
    char ahost[MAXHOSTNAMELEN];
    register char *p;
    
    while (fgets(ahost, sizeof (ahost), hostf)) {
	p = ahost;
	while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0') {
	    *p = islower(*p) ? toupper(*p) : *p;
	    p++;
	}
	if (*p == ' ' || *p == '\t') {
	    *p++ = '\0';
	    while (*p == ' ' || *p == '\t')
	      p++;
	    user = p;
	    while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0')
	      p++;
	} else
	  user = p;
	*p = '\0';
	if (_checkhost(rhost, ahost, baselen) &&
	    !strcmp(ruser, *user ? user : luser)) {
	    return (0);
	}
    }
    return (-1);
}
#endif	/* convex */



_checkhost(rhost, lhost, len)
     char *rhost, *lhost;
     int len;
{
    static char ldomain[MAXHOSTNAMELEN + 1];
    static char *domainp = NULL;
    static int nodomain = 0;
    register char *cp;
    
    if (len == -1)
      return(!strcmp(rhost, lhost));
    if (strncmp(rhost, lhost, len))
      return(0);
    if (!strcmp(rhost, lhost))
      return(1);
    if (*(lhost + len) != '\0')
      return(0);
    if (nodomain)
      return(0);
    if (!domainp) {
	if (gethostname(ldomain, sizeof(ldomain)) == -1) {
	    nodomain = 1;
	    return(0);
	}
	ldomain[MAXHOSTNAMELEN] = NULL;
	if ((domainp = strchr(ldomain, '.')) == (char *)NULL) {
	    nodomain = 1;
	    return(0);
	}
	for (cp = ++domainp; *cp; ++cp)
	  if (islower(*cp))
	    *cp = toupper(*cp);
    }
    return(!strcmp(domainp, rhost + len +1));
    
}
#endif /* ! sysvimp */



#if defined (hpux)
int setreuid(real,eff)
     int real,eff;
{
    int tmpint = -1;
    return(setresuid(real,eff,tmpint));
}
#endif



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



#ifdef SYSV

int killpg(pid,sig)
     int pid,sig;
{
    
    if ( pid >= 0)
      pid *= -1;
    return(kill(pid,sig));
}

#endif
