/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)rcmd.c	5.22 (Berkeley) 6/1/90";
#endif /* LIBC_SCCS and not lint */

/*
 * 2-14-91        ka
 * Modified sources to add SPX strong authentication, called fcmd.c
 *
 * 5-24-91          ka
 * Modified sources to remove SPX and Kerberos specific authentication.
 * Replaced with GSS API
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <netdb.h>
#include <errno.h>

#include <syslog.h>
#include "gssapi_defs.h"

#define START_PORT    5120

#define TOKEN_MAJIC_NUMBER_BYTE0    1
#define TOKEN_MAJIC_NUMBER_BYTE1    1

extern	errno;
char	*index();

fcmd(sock, ahost, rport, locuser, remuser, cmd, fd2p, targetname,
context_handle, mutual_flag, deleg_flag, debugflag)
	int  *sock;
	char **ahost;
	int rport;
	char *locuser, *remuser, *cmd;
	int *fd2p;
        char *targetname;
	int    *context_handle;
	int mutual_flag, deleg_flag, debugflag;
{
	int s, timo = 1, pid;
	long oldmask;
	struct sockaddr_in sin, sin2, from;
	char c;
	int lport = START_PORT;
	struct hostent *hp;
	fd_set reads;

	unsigned char token[GSS_C_MAX_TOKEN], chanbinding[8];
	unsigned char *charp;
	char tokenheader[4], recv_tokenheader[4];
	int  tokenlen, i, j, status = 0, hostlen, xcc, cc, mutual_len;
	int  chanbinding_len, replay_flag=0, seq_flag=0;
        char hostname[GSS_C_MAX_PRINTABLE_NAME];
        char mutual_resp[GSS_C_MAX_TOKEN];
        char targ_printable[GSS_C_MAX_PRINTABLE_NAME];
/*
 * GSS API support
 */
	gss_OID_set   actual_mechs;
	gss_OID       actual_mech_type, output_name_type;
	gss_cred_id_t gss_cred_handle;
        gss_ctx_id_t  actual_ctxhandle;
	int           msg_ctx = 0, new_status;
	int           req_flags = 0, ret_flags, lifetime_rec, major_status;
	gss_buffer_desc  output_token, input_token, input_name_buffer;
	gss_buffer_desc  output_name_buffer, status_string;
	gss_name_t    desired_targname;
	gss_channel_bindings  input_chan_bindings;

	pid = getpid();
	hp = gethostbyname(*ahost);
	if (hp == 0) {
	        fprintf(stderr, "%s : unknown host\n", *ahost);
		return (-1);
	}
	*ahost = hp->h_name;
	oldmask = sigblock(sigmask(SIGURG));
	for (;;) {
		s = rresvport(&lport);
		if (s < 0) {
			if (errno == EAGAIN)
				fprintf(stderr, "socket: All ports in use\n");
			else
				perror("rcmd: socket");
			sigsetmask(oldmask);
			return (-1);
		}
		fcntl(s, F_SETOWN, pid);
		sin.sin_family = hp->h_addrtype;
		bcopy(hp->h_addr_list[0], (caddr_t)&sin.sin_addr, hp->h_length);
		sin.sin_port = rport;
		if (connect(s, (caddr_t)&sin, sizeof (sin), 0) >= 0)
			break;
		(void) close(s);
		if (errno == EADDRINUSE) {
			lport--;
			continue;
		}
		if (errno == ECONNREFUSED && timo <= 16) {
			sleep(timo);
			timo *= 2;
			continue;
		}
		if (hp->h_addr_list[1] != NULL) {
			int oerrno = errno;

			fprintf(stderr,
			    "connect to address %s: ", inet_ntoa(sin.sin_addr));
			errno = oerrno;
			perror(0);
			hp->h_addr_list++;
			bcopy(hp->h_addr_list[0], (caddr_t)&sin.sin_addr,
			    hp->h_length);
			fprintf(stderr, "Trying %s...\n",
				inet_ntoa(sin.sin_addr));
			continue;
		}
		perror(hp->h_name);
		sigsetmask(oldmask);
		return (-1);
	}

	lport--;
	if (fd2p == 0) {
		write(s, "", 1);
		lport = 0;
	} else {
		char num[8];
		int s2 = rresvport(&lport), s3;
		int len = sizeof (from);

		if (s2 < 0)
			goto bad;
		listen(s2, 1);
		(void) sprintf(num, "%d", lport);
		if (write(s, num, strlen(num)+1) != strlen(num)+1) {
			perror("write: setting up stderr");
			(void) close(s2);
			goto bad;
		}
		FD_ZERO(&reads);
		FD_SET(s, &reads);
		FD_SET(s2, &reads);
		errno = 0;
		if (select(32, &reads, 0, 0, 0) < 1 ||
		    !FD_ISSET(s2, &reads)) {
			if (errno != 0)
				perror("select: setting up stderr");
			else
			    fprintf(stderr,
				"select: protocol failure in circuit setup.\n");
			(void) close(s2);
			goto bad;
		}
		s3 = accept(s2, &from, &len, 0);
		(void) close(s2);
		if (s3 < 0) {
			perror("accept");
			lport = 0;
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
/*
 * GSS API authentication
 *   import name
 *   init context
 *   send token
 *   if (mutual) init context
 *
 */
	{
	  char  myhost[32];
	  int  from_addr=0, to_addr=0, myhostlen, j;
	  struct hostent *my_hp;

	  strcpy(targ_printable, "SERVICE:rlogin@");
	  strcat(targ_printable, targetname);
	  if (debugflag) {
	    printf("call gss_import_name for '%s'\n", targ_printable);
	  }

	  input_name_buffer.length = strlen(targ_printable);
	  input_name_buffer.value = targ_printable;

	  major_status = gss_import_name(&status,
					 &input_name_buffer,
					 GSS_C_NULL_OID,
					 &desired_targname);

	  major_status = gss_display_name(&status,
					  desired_targname,
					  &output_name_buffer,
					  &output_name_type);

	  printf("target is '%s'\n", output_name_buffer.value);

	  major_status = gss_release_buffer(&status, &output_name_buffer);

	  j=gethostname(myhost, sizeof(myhost));
	  my_hp=gethostbyname(myhost);
	  if (my_hp != 0) {
	    bcopy(my_hp->h_addr_list[0],
		  (caddr_t)&sin2.sin_addr, my_hp->h_length);
#ifdef ultrix
	    from_addr = sin2.sin_addr.S_un.S_addr;
#else
	    from_addr = sin2.sin_addr.s_addr;
#endif
	    from_addr = htonl(from_addr);
	  }
#ifdef ultrix
	  to_addr = sin.sin_addr.S_un.S_addr;
#else
	  to_addr = sin.sin_addr.s_addr;
#endif
	  to_addr = htonl(to_addr);

	  input_chan_bindings = (gss_channel_bindings)
	    malloc(sizeof(gss_channel_bindings_desc));

	  input_chan_bindings->initiator_addrtype = GSS_C_AF_INET;
	  input_chan_bindings->initiator_address.length = 4;
	  input_chan_bindings->initiator_address.value = (char *) malloc(4);
	  input_chan_bindings->initiator_address.value[0] = ((from_addr
& 0xff000000) >> 24);
	  input_chan_bindings->initiator_address.value[1] = ((from_addr
& 0xff0000) >> 16);
	  input_chan_bindings->initiator_address.value[2] = ((from_addr
& 0xff00) >> 8);
	  input_chan_bindings->initiator_address.value[3] = (from_addr & 0xff);
	  input_chan_bindings->acceptor_addrtype = GSS_C_AF_INET;
	  input_chan_bindings->acceptor_address.length = 4;
	  input_chan_bindings->acceptor_address.value = (char *) malloc(4);
	  input_chan_bindings->acceptor_address.value[0] = ((to_addr &
0xff000000) >> 24);
	  input_chan_bindings->acceptor_address.value[1] = ((to_addr &
0xff0000) >> 16);
	  input_chan_bindings->acceptor_address.value[2] = ((to_addr &
0xff00) >> 8);
	  input_chan_bindings->acceptor_address.value[3] = (to_addr & 0xff);
	  input_chan_bindings->application_data.length = 0;
	}

	req_flags = 0;
	if (deleg_flag)  req_flags = req_flags | 1;
	if (mutual_flag) req_flags = req_flags | 2;
	if (replay_flag) req_flags = req_flags | 4;
	if (seq_flag)    req_flags = req_flags | 8;

	major_status = gss_init_sec_context(&status,         /* minor status */
					GSS_C_NO_CREDENTIAL, /* cred handle */
					&actual_ctxhandle,   /* ctx handle */
					desired_targname,    /* target name */
					GSS_C_NULL_OID,      /* mech type */
					req_flags,           /* req flags */
					0,                   /* time req */
					input_chan_bindings, /* chan binding */
					GSS_C_NO_BUFFER,     /* input token */
					&actual_mech_type,   /* actual mech */
					&output_token,       /* output token */
					&ret_flags,          /* ret flags */
					&lifetime_rec);      /* time rec */


	if ((major_status!=GSS_S_COMPLETE)&&
	    (major_status!=GSS_S_CONTINUE_NEEDED)) {
	  gss_display_status(&new_status,
			     status,
			     GSS_C_MECH_CODE,
			     GSS_C_NULL_OID,
			     &msg_ctx,
			     &status_string);
	  printf("%s\n", status_string.value);
	  return(-1);
	}

        tokenheader[0] = TOKEN_MAJIC_NUMBER_BYTE0;
        tokenheader[1] = TOKEN_MAJIC_NUMBER_BYTE1;
	tokenheader[2] = ((output_token.length & 0xff00) >> 8);
	tokenheader[3] = (output_token.length & 0xff);

        j = sphinx_net_write(s, tokenheader, 4);

        j = sphinx_net_write(s, output_token.value, output_token.length);

	(void) write(s, locuser, strlen(locuser)+1);
	(void) write(s, remuser, strlen(remuser)+1);
	(void) write(s, cmd, strlen(cmd)+1);

	if (read(s, &c, 1) != 1) {
		perror(*ahost);
		goto bad2;
	}

	i = 0;
        if (major_status == GSS_S_CONTINUE_NEEDED) {

	  xcc = 4;
	  while (xcc > 0) {
	    if ((cc = read(s, &recv_tokenheader[i], xcc)) < 0) {
	      syslog(LOG_INFO,"read(s, recv_tokenheader, %d): %m",xcc);
	      break;
	    }
	    i +=cc;
	    xcc -= cc;
	  }

	  if ((recv_tokenheader[0] != TOKEN_MAJIC_NUMBER_BYTE0) ||
	    (recv_tokenheader[1] != TOKEN_MAJIC_NUMBER_BYTE1)) {
	    printf("illegal mutual response token format\n");
	    syslog(LOG_INFO, "cannot go from v2.1 client to v2.0 server");
	    return(-1);
	  }
	  xcc = recv_tokenheader[2] * 256 + recv_tokenheader[3];

	  mutual_len = 0;
	  while (xcc > 0) {
	    if ((cc = read(s, &mutual_resp[mutual_len], xcc)) < 0) {
	      syslog(LOG_INFO,"read(s, mutual_resp, %d): %m",xcc);
	      break;
	    }
	    mutual_len +=cc;
	    xcc -= cc;
	  }

	  input_token.length = mutual_len;
	  input_token.value = mutual_resp;

	  major_status = gss_init_sec_context(&status,       /* minor status */
					GSS_C_NO_CREDENTIAL, /* cred handle */
					&actual_ctxhandle,   /* ctx handle */
					desired_targname,    /* target name */
					GSS_C_NULL_OID,      /* mech type */
					req_flags,           /* req flags */
					0,                   /* time req */
					input_chan_bindings, /* chan binding */
					&input_token,        /* input token */
					&actual_mech_type,   /* actual mech */
					&output_token,       /* output token */
					&ret_flags,          /* ret flags */
					&lifetime_rec);      /* time rec */

	  if (major_status!=GSS_S_COMPLETE) {
	    gss_display_status(&new_status,
			       status,
			       GSS_C_MECH_CODE,
			       GSS_C_NULL_OID,
			       &msg_ctx,
			       &status_string);
	    printf("%s\n", status_string.value);
	    return(-1);
	  }
	}

	major_status = gss_release_name(&status, desired_targname);

#ifdef SPX_CHALLENGE
	/*
	 * if trying to login to root account, make up response proving
	 * that the user is interactive.
	 *
	 * response is the signed mutual response with the user's long term
	 * private key.
	 *
	 */
	if (strcmp(remuser, "root")==0) {
	  major_status = spx_make_response(&status,
					   GSS_C_NO_CREDENTIAL,
					   actual_ctxhandle,
					   token,
					   &tokenlen);

	  if (major_status != GSS_S_COMPLETE) {
	    gss_display_status(&new_status,
			       status,
			       GSS_C_MECH_CODE,
			       GSS_C_NULL_OID,
			       &msg_ctx,
			       &status_string);
	    printf("%s\n", status_string.value);
	    return(-1);
	  }

	  tokenheader[0] = TOKEN_MAJIC_NUMBER_BYTE0;
	  tokenheader[1] = TOKEN_MAJIC_NUMBER_BYTE1;
	  tokenheader[2] = ((tokenlen & 0xff00) >> 8);
	  tokenheader[3] = (tokenlen & 0xff);

	  j = sphinx_net_write(s, tokenheader, 4);

	  charp = token;
	  j = sphinx_net_write(s, (char *)charp, tokenlen);

	}
#endif  /* SPX_CHALLENGE */
	*context_handle = actual_ctxhandle;

	if (c != 0) {
		while (read(s, &c, 1) == 1) {
			(void) write(2, &c, 1);
			if (c == '\n')
				break;
		}
		goto bad2;
	}
	sigsetmask(oldmask);
	return (s);
bad2:
	if (lport)
		(void) close(*fd2p);
bad:
	(void) close(s);
	sigsetmask(oldmask);
	return (-1);
}

rresvport(alport)
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
		if (bind(s, (caddr_t)&sin, sizeof (sin)) >= 0)
			return (s);
		if (errno != EADDRINUSE) {
			(void) close(s);
			return (-1);
		}
		(*alport)--;
		if (*alport == IPPORT_RESERVED/2) {
			(void) close(s);
			errno = EAGAIN;		/* close */
			return (-1);
		}
	}
}

int	_check_rhosts_file = 1;

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

	sp = rhost;
	p = fhost;
	while (*sp) {
		if (*sp == '.') {
			if (baselen == -1)
				baselen = sp - rhost;
			*p++ = *sp++;
		} else {
			*p++ = isupper(*sp) ? tolower(*sp++) : *sp++;
		}
	}
	*p = '\0';
	hostf = superuser ? (FILE *)0 : fopen("/etc/hosts.equiv", "r");
again:
	if (hostf) {
		if (!_validuser(hostf, fhost, luser, ruser, baselen)) {
			(void) fclose(hostf);
			return(0);
		}
		(void) fclose(hostf);
	}
	if (first == 1 && (_check_rhosts_file || superuser)) {
		struct stat sbuf;
		struct passwd *pwd;
		char pbuf[MAXPATHLEN];

		first = 0;
		if ((pwd = getpwnam(luser)) == NULL)
			return(-1);
		(void)strcpy(pbuf, pwd->pw_dir);
		(void)strcat(pbuf, "/.rhosts");
		if ((hostf = fopen(pbuf, "r")) == NULL)
			return(-1);
		/*
		 * if owned by someone other than user or root or if
		 * writeable by anyone but the owner, quit
		 */
		if (fstat(fileno(hostf), &sbuf) ||
		    sbuf.st_uid && sbuf.st_uid != pwd->pw_uid ||
		    sbuf.st_mode&022) {
			fclose(hostf);
			return(-1);
		}
		goto again;
	}
	return (-1);
}

/* don't make static, used by lpd(8) */
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
			*p = isupper(*p) ? tolower(*p) : *p;
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

static
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
		if ((domainp = index(ldomain, '.')) == (char *)NULL) {
			nodomain = 1;
			return(0);
		}
		for (cp = ++domainp; *cp; ++cp)
			if (isupper(*cp))
				*cp = tolower(*cp);
	}
	return(!strcmp(domainp, rhost + len +1));
}
