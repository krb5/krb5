/*
 * Copyright (c) 1985, 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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

#ifndef lint
static char sccsid[] = "@(#)ftp.c	5.38 (Berkeley) 4/22/91";
#endif /* not lint */

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <sys/timeb.h>
#include <time.h>
#include <crtdbg.h>
#undef ERROR
#define NOSTBLKSIZE

#define popen _popen
#define pclose _pclose
#define sleep(secs) Sleep(secs * 1000)
int gettimeofday(struct timeval *tv, void *tz);

#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef _WIN32
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#ifndef KRB5_KRB4_COMPAT
/* krb.h gets this, and Ultrix doesn't protect vs multiple inclusion */
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <sys/time.h>
#include <sys/file.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <pwd.h>
#endif

#include <arpa/ftp.h>
#include <arpa/telnet.h>

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#include <port-sockets.h>

#ifndef L_SET
#define L_SET 0
#endif
#ifndef L_INCR
#define L_INCR 1
#endif

#ifdef KRB5_KRB4_COMPAT
#include <krb.h>

KTEXT_ST ticket;
CREDENTIALS cred;
Key_schedule schedule;
MSG_DAT msg_data;
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
#include <gssapi/gssapi.h>
/* need to include the krb5 file, because we're doing manual fallback
   from the v2 mech to the v2 mech.  Once there's real negotiation,
   we can be generic again. */
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
gss_ctx_id_t gcontext;
#endif /* GSSAPI */

static int kerror;	/* XXX needed for all auth types */

char	*auth_type;	/* Authentication succeeded?  If so, what type? */

unsigned int maxbuf, actualbuf;
unsigned char *ucbuf;
 
#define DEFINITIONS
#include "ftp_var.h"
#include "secure.h"

#ifdef GSSAPI
void user_gss_error (OM_uint32, OM_uint32, char *);
#endif

static void proxtrans (char *, char *, char *);
static int initconn (void);
static void ptransfer (char *, long, struct timeval *, struct timeval *);
static void abort_remote (FILE *);
static void tvsub (struct timeval *, struct timeval *, struct timeval *);
static char *gunique (char *);

struct	sockaddr_in hisctladdr;
struct	sockaddr_in hisdataaddr;
struct	sockaddr_in data_addr;
SOCKET	data = -1;
int	abrtflag = 0;
int	ptflag = 0;
struct	sockaddr_in myctladdr;
#ifndef _WIN32
uid_t	getuid();
#endif
sig_t	lostpeer();
off_t	restart_point = 0;
jmp_buf ptabort;

#ifndef HAVE_STRERROR
#define strerror(error) (sys_errlist[error])
#ifdef NEED_SYS_ERRLIST
extern char *sys_errlist[];
#endif
#endif

extern int connected;

#define herror()	printf("unknown host\n")

FILE	*cin, *cout;
FILE	*dataconn (char *);

char *
hookup(char* host, int port)
{
	register struct hostent *hp = 0;
	int s;
	socklen_t len;
#ifdef IP_TOS
#ifdef IPTOS_LOWDELAY
	int tos;
#endif
#endif
	static char hostnamebuf[80];

	memset((char *)&hisctladdr, 0, sizeof (hisctladdr));
	hisctladdr.sin_addr.s_addr = inet_addr(host);
	if (hisctladdr.sin_addr.s_addr != -1) {
		hisctladdr.sin_family = AF_INET;
		(void) strncpy(hostnamebuf, host, sizeof(hostnamebuf));
	} else {
		hp = gethostbyname(host);
		if (hp == NULL) {
			fprintf(stderr, "ftp: %s: ", host);
			herror();
			code = -1;
			return((char *) 0);
		}
		hisctladdr.sin_family = hp->h_addrtype;
		memcpy(&hisctladdr.sin_addr, hp->h_addr_list[0],
		       sizeof(hisctladdr.sin_addr));
		(void) strncpy(hostnamebuf, hp->h_name, sizeof(hostnamebuf));
	}
	hostname = hostnamebuf;
	s = socket(hisctladdr.sin_family, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		PERROR_SOCKET("ftp: socket");
		code = -1;
		return (0);
	}
	hisctladdr.sin_port = port;
	while (connect(s, (struct sockaddr *)&hisctladdr, sizeof (hisctladdr)) == SOCKET_ERROR) {
		if (hp && hp->h_addr_list[1]) {
			int oerrno = SOCKET_ERRNO;
#ifndef _WIN32
			extern char *inet_ntoa();
#endif
			fprintf(stderr, "ftp: connect to address %s: ",
				inet_ntoa(hisctladdr.sin_addr));
			SOCKET_SET_ERRNO(oerrno);
			PERROR_SOCKET((char *) 0);
			hp->h_addr_list++;
			memcpy(&hisctladdr.sin_addr,
			       hp->h_addr_list[0], 
			       sizeof(hisctladdr.sin_addr));
			fprintf(stdout, "Trying %s...\n",
				inet_ntoa(hisctladdr.sin_addr));
			(void) closesocket(s);
			s = socket(hisctladdr.sin_family, SOCK_STREAM, 0);
			if (s == INVALID_SOCKET) {
				PERROR_SOCKET("ftp: socket");
				code = -1;
				return (0);
			}
			continue;
		}
		PERROR_SOCKET("ftp: connect");
		code = -1;
		goto bad;
	}
	len = sizeof (myctladdr);
	if (getsockname(s, (struct sockaddr *)&myctladdr, &len) == SOCKET_ERROR) {
		PERROR_SOCKET("ftp: getsockname");
		code = -1;
		goto bad;
	}
#ifdef IP_TOS
#ifdef IPTOS_LOWDELAY
	tos = IPTOS_LOWDELAY;
	if (setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int)) == SOCKET_ERROR) {
		PERROR_SOCKET("ftp: setsockopt TOS (ignored)");
	}
#endif
#endif
	cin = FDOPEN_SOCKET(s, "r");
	cout = FDOPEN_SOCKET(s, "w");
	if (cin == NULL || cout == NULL) {
		fprintf(stderr, "ftp: fdopen failed.\n");
		if (cin) {
			(void) FCLOSE_SOCKET(cin);
			cin = NULL;
		}
		if (cout) {
			(void) FCLOSE_SOCKET(cout);
			cout = NULL;
		}
		code = -1;
		goto bad;
	}
	if (verbose)
		printf("Connected to %s.\n", hostname);
	if (getreply(0) > 2) { 	/* read startup message from server */
		if (cin) {
			(void) FCLOSE_SOCKET(cin);
			cin = NULL;
		}
		if (cout) {
			(void) FCLOSE_SOCKET(cout);
			cout = NULL;
		}
		code = -1;
		goto bad;
	}
#ifdef SO_OOBINLINE
	{
	int on = 1;

	if (setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof(on))
		== SOCKET_ERROR && debug) {
			PERROR_SOCKET("ftp: setsockopt");
		}
	}
#endif /* SO_OOBINLINE */

	return (hostname);
bad:
	(void) closesocket(s);
	return ((char *)0);
}

int login(char *host)
{
	char tmp[80];
	char *l_user, *pass, *l_acct, *getenv(), *getlogin();
	int n, aflag = 0;

	l_user = pass = l_acct = 0;
	if (ruserpass(host, &l_user, &pass, &l_acct) < 0) {
		code = -1;
		return(0);
	}
	while (l_user == NULL) {
		char *myname;

		myname = getenv("LOGNAME");
		if (myname == NULL)
			myname = getenv("USER");
#ifndef _WIN32
		if (myname == NULL)
			myname = getlogin();
		if (myname == NULL) {
			struct passwd *pp = getpwuid(getuid());

			if (pp != NULL)
				myname = pp->pw_name;
		}
#else
		if (myname == NULL) {
			static char buffer[200];
			int len = sizeof(buffer);
			if (GetUserName(buffer, &len))
				myname = buffer;
			else
				myname = "<Unknown>";
		}
#endif
		if (myname)
			printf("Name (%s:%s): ", host, myname);
		else
			printf("Name (%s): ", host);
		(void) fgets(tmp, sizeof(tmp) - 1, stdin);
		tmp[strlen(tmp) - 1] = '\0';
		if (*tmp == '\0')
			l_user = myname;
		else
			l_user = tmp;
	}
	n = command("USER %s", l_user);
	if (n == COMPLETE) {
	        /* determine if we need to send a dummy password */
		int oldverbose = verbose;

		verbose = 0;
		if (command("PWD") != COMPLETE) {
			verbose = oldverbose;
			command("PASS dummy");
		} else {
			verbose = oldverbose;
		}
	}
	else if (n == CONTINUE) {
#ifndef NOENCRYPTION
		int oldclevel;
#endif
		if (pass == NULL)
			pass = mygetpass("Password:");
#ifndef NOENCRYPTION
		oldclevel = clevel;
		clevel = PROT_P;
#endif
		n = command("PASS %s", pass);
#ifndef NOENCRYPTION
		/* level may have changed */
		if (clevel == PROT_P) clevel = oldclevel;
#endif
	}
	if (n == CONTINUE) {
		aflag++;
		l_acct = mygetpass("Account:");
		n = command("ACCT %s", l_acct);
	}
	if (n != COMPLETE) {
		fprintf(stderr, "Login failed.\n");
		return (0);
	}
	if (!aflag && l_acct != NULL)
		(void) command("ACCT %s", l_acct);
	if (proxy)
		return(1);
	for (n = 0; n < macnum; ++n) {
		if (!strcmp("init", macros[n].mac_name)) {
			(void) strcpy(line, "$init");
			makeargv();
			domacro(margc, margv);
			break;
		}
	}
	return (1);
}

static sigtype
cmdabort(int sig)
{
	printf("\n");
	(void) fflush(stdout);
	abrtflag++;
	if (ptflag)
		longjmp(ptabort,1);
}

static int secure_command(char* cmd)
{
	unsigned char in[FTP_BUFSIZ], out[FTP_BUFSIZ];
	int length;

	if (auth_type && clevel != PROT_C) {
#ifdef KRB5_KRB4_COMPAT
		if (strcmp(auth_type, "KERBEROS_V4") == 0)
		    if ((length = clevel == PROT_P ?
			krb_mk_priv((unsigned char *)cmd, (unsigned char *)out,
				strlen(cmd), schedule,
				&cred.session, &myctladdr, &hisctladdr)
		      : krb_mk_safe((unsigned char *)cmd, (unsigned char *)out,
				strlen(cmd), &cred.session,
				&myctladdr, &hisctladdr)) == -1) {
			fprintf(stderr, "krb_mk_%s failed for KERBEROS_V4\n",
					clevel == PROT_P ? "priv" : "safe");
			return(0);
		    }
#endif /* KRB5_KRB4_COMPAT */
#ifdef GSSAPI
		/* secure_command (based on level) */
		if (strcmp(auth_type, "GSSAPI") == 0) {
			gss_buffer_desc in_buf, out_buf;
			OM_uint32 maj_stat, min_stat;
			int conf_state;
/* clevel = PROT_P; */
			in_buf.value = cmd;
			in_buf.length = strlen(cmd) + 1;
			maj_stat = gss_seal(&min_stat, gcontext,
					    (clevel==PROT_P), /* private */
					    GSS_C_QOP_DEFAULT,
					    &in_buf, &conf_state,
					    &out_buf);
			if (maj_stat != GSS_S_COMPLETE) {
				/* generally need to deal */
				user_gss_error(maj_stat, min_stat,
					       (clevel==PROT_P)?
						 "gss_seal ENC didn't complete":
						 "gss_seal MIC didn't complete");
			} else if ((clevel == PROT_P) && !conf_state) {
				fprintf(stderr, 
					"GSSAPI didn't encrypt message");
			} else {
				if (debug)
				  fprintf(stderr, "sealed (%s) %d bytes\n",
					  clevel==PROT_P?"ENC":"MIC", 
					  out_buf.length);
				length=out_buf.length;
				memcpy(out, out_buf.value, out_buf.length);
				gss_release_buffer(&min_stat, &out_buf);
			}
		}
#endif /* GSSAPI */
		/* Other auth types go here ... */
		kerror = radix_encode(out, in, &length, 0);
		if (kerror) {
			fprintf(stderr,"Couldn't base 64 encode command (%s)\n",
					radix_error(kerror));
			return(0);
		}
		fprintf(cout, "%s %s", clevel == PROT_P ? "ENC" : "MIC", in);
		if(debug) 
		  fprintf(stderr, "secure_command(%s)\nencoding %d bytes %s %s\n",
			  cmd, length, clevel==PROT_P ? "ENC" : "MIC", in);
	} else	fputs(cmd, cout);
	fprintf(cout, "\r\n");
	(void) fflush(cout);
	return(1);
}

int command(char *fmt, ...)
{
	char in[FTP_BUFSIZ];
	va_list ap;
	int r;
	sig_t oldintr;

	abrtflag = 0;
	if (debug) {
		if (proxflag) printf("%s ", hostname);
		printf("---> ");
		va_start(ap, fmt);
		if (strncmp("PASS ", fmt, 5) == 0)
			printf("PASS XXXX");
		else 
			vfprintf(stdout, fmt, ap);
		va_end(ap);
		printf("\n");
		(void) fflush(stdout);
	}
	if (cout == NULL) {
		perror ("No control connection for command");
		code = -1;
		return (0);
	}
	oldintr = signal(SIGINT, cmdabort);
	va_start(ap, fmt);
	vsprintf(in, fmt, ap);
	va_end(ap);
again:	if (secure_command(in) == 0)
		return(0);
	cpend = 1;
	r = getreply(!strcmp(fmt, "QUIT"));
#ifndef NOENCRYPTION
	if (r == 533 && clevel == PROT_P) {
		fprintf(stderr,
			"ENC command not supported at server; retrying under MIC...\n");
		clevel = PROT_S;
		goto again;
	}
#endif
	if (abrtflag && oldintr && oldintr != SIG_IGN)
		(*oldintr)(SIGINT);
	(void) signal(SIGINT, oldintr);
	return(r);
}

char reply_string[FTP_BUFSIZ];		/* last line of previous reply */

/* for parsing replies to the ADAT command */
char *reply_parse, reply_buf[FTP_BUFSIZ], *reply_ptr;

#include <ctype.h>

int getreply(int expecteof)
{
	register int i, c, n;
	register int dig;
	register char *cp;
	int originalcode = 0, continuation = 0;
	sig_t oldintr;
	int pflag = 0;
	char *pt = pasv;
	char ibuf[FTP_BUFSIZ], obuf[FTP_BUFSIZ];
	int safe = 0;
#ifndef strpbrk
	extern char *strpbrk();
#endif
#ifndef strstr
	extern char *strstr();
#endif

	ibuf[0] = '\0';
	if (reply_parse) reply_ptr = reply_buf;
	oldintr = signal(SIGINT, cmdabort);
	for (;;) {
		obuf[0] = '\0';
		dig = n = code = i = 0;
		cp = reply_string;
		while ((c = ibuf[0] ? ibuf[i++] : getc(cin)) != '\n') {
			if (c == IAC) {     /* handle telnet commands */
				switch (c = getc(cin)) {
				case WILL:
				case WONT:
					c = getc(cin);
					fprintf(cout, "%c%c%c", IAC, DONT, c);
					(void) fflush(cout);
					break;
				case DO:
				case DONT:
					c = getc(cin);
					fprintf(cout, "%c%c%c", IAC, WONT, c);
					(void) fflush(cout);
					break;
				default:
					break;
				}
				continue;
			}
			dig++;
			if (c == EOF) {
				if (expecteof) {
					(void) signal(SIGINT,oldintr);
					code = 221;
					return (0);
				}
				lostpeer();
				if (verbose) {
					printf("421 Service not available, remote server has closed connection\n");
					(void) fflush(stdout);
				}
				code = 421;
				return(4);
			}
			if (n == 0)
				n = c;
			if (auth_type && !ibuf[0] &&
				(n == '6' || continuation)) {
			    if (c != '\r' && dig > 4)
				obuf[i++] = c;
			} else {
			    if (auth_type && !ibuf[0] && dig == 1 && verbose)
			printf("Unauthenticated reply received from server:\n");
			    if (reply_parse) *reply_ptr++ = c;
			    if (c != '\r' && (verbose > 0 ||
				(verbose > -1 && n == '5' && dig > 4))) {
				    if (proxflag &&
					(dig == 1 || (dig == 5 && verbose == 0)))
						printf("%s:",hostname);
				    (void) putchar(c);
			    }
			}
			if (auth_type && !ibuf[0] && n != '6') continue;
			if (dig < 4 && isdigit(c))
				code = code * 10 + (c - '0');
			if (!pflag && code == 227)
				pflag = 1;
			if (dig > 4 && pflag == 1 && isdigit(c))
				pflag = 2;
			if (pflag == 2) {
				if (c != '\r' && c != ')')
					*pt++ = c;
				else {
					*pt = '\0';
					pflag = 3;
				}
			}
			if (dig == 4 && c == '-' && n != '6') {
				if (continuation)
					code = 0;
				continuation++;
			}
			if (cp < &reply_string[sizeof(reply_string) - 1])
				*cp++ = c;
		}
		if (auth_type && !ibuf[0] && n != '6')
			return(getreply(expecteof));
		ibuf[0] = obuf[i] = '\0';
		if (code && n == '6') {
		    if (code != 631 && code != 632 && code != 633) {
			printf("Unknown reply: %d %s\n", code, obuf);
			n = '5';
		    } else safe = (code == 631);
		}
		if (obuf[0])	/* if there is a string to decode */
		    if (!auth_type) {
			printf("Cannot decode reply:\n%d %s\n", code, obuf);
			n = '5';
		    }
#ifdef NOENCRYPTION
		    else if (code == 632) {
			printf("Cannot decrypt %d reply: %s\n", code, obuf);
			n = '5';
		    }
#endif
#ifdef NOCONFIDENTIAL
		    else if (code == 633) {
			printf("Cannot decrypt %d reply: %s\n", code, obuf);
			n = '5';
		    }
#endif
		    else {
			int len;
			kerror = radix_encode((unsigned char *)obuf,
					      (unsigned char *)ibuf, 
					      &len, 1);
			if (kerror) {
			    printf("Can't base 64 decode reply %d (%s)\n\"%s\"\n",
					code, radix_error(kerror), obuf);
			    n = '5';
			}
#ifdef KRB5_KRB4_COMPAT
			else if (strcmp(auth_type, "KERBEROS_V4") == 0)
				if ((kerror = safe ?
				  krb_rd_safe((unsigned char *)ibuf, 
					      (unsigned int) len,
					      &cred.session,
					      &hisctladdr, 
					      &myctladdr, &msg_data)
				: krb_rd_priv((unsigned char *)ibuf, 
					      (unsigned int) len,
					      schedule, &cred.session,
					      &hisctladdr, &myctladdr,
					      &msg_data))
				!= KSUCCESS) {
				  printf("%d reply %s! (krb_rd_%s: %s)\n", code,
					safe ? "modified" : "garbled",
					safe ? "safe" : "priv",
					krb_get_err_text(kerror));
				  n = '5';
				} else {
				  if (debug) printf("%c:", safe ? 'S' : 'P');
				  if(msg_data.app_length < sizeof(ibuf) - 2) {
				    memcpy(ibuf, msg_data.app_data,
					   msg_data.app_length);
				    strcpy(&ibuf[msg_data.app_length], "\r\n");
				  } else {
			            printf("Message too long!");
				  }
				  continue;
				}
#endif
#ifdef GSSAPI
			else if (strcmp(auth_type, "GSSAPI") == 0) {
				gss_buffer_desc xmit_buf, msg_buf;
				OM_uint32 maj_stat, min_stat;
				int conf_state;
				xmit_buf.value = ibuf;
				xmit_buf.length = len;
				/* decrypt/verify the message */
				conf_state = safe;
				maj_stat = gss_unseal(&min_stat, gcontext, 
						      &xmit_buf, &msg_buf, 
						      &conf_state, NULL);
				if (maj_stat != GSS_S_COMPLETE) {
				  user_gss_error(maj_stat, min_stat, 
						 "failed unsealing reply");
				  n = '5';
				} else {
				  if(msg_buf.length < sizeof(ibuf) - 2 - 1) {
				    memcpy(ibuf, msg_buf.value, 
					   msg_buf.length);
				    strcpy(&ibuf[msg_buf.length], "\r\n");
				  } else {
				    user_gss_error(maj_stat, min_stat, 
						   "reply was too long");
				  }
				  gss_release_buffer(&min_stat,&msg_buf);
				  continue;
				}
			}
#endif
			/* Other auth types go here... */
		    }
		else
		if (verbose > 0 || (verbose > -1 && n == '5')) {
			(void) putchar(c);
			(void) fflush (stdout);
		}
		if (continuation && code != originalcode) {
			if (originalcode == 0)
				originalcode = code;
			continue;
		}
		*cp = '\0';
		if (n != '1')
			cpend = 0;
		(void) signal(SIGINT,oldintr);
		if (code == 421 || originalcode == 421)
			lostpeer();
		if (abrtflag && oldintr && oldintr != cmdabort && oldintr != SIG_IGN)
			(*oldintr)(SIGINT);
		if (reply_parse) {
			*reply_ptr = '\0';
			reply_ptr = strstr(reply_buf, reply_parse);
			if (reply_ptr) {
				reply_parse = reply_ptr + strlen(reply_parse);
				reply_ptr = strpbrk(reply_parse, " \r");
				if (reply_ptr)
					*reply_ptr = '\0';
			} else reply_parse = reply_ptr;
		}
		return (n - '0');
	}
}

static int empty(fd_set *mask, int sec)
{
	struct timeval t;

	t.tv_sec = (long) sec;
	t.tv_usec = 0;
	return(select(32, mask, (fd_set *) 0, (fd_set *) 0, &t));
}

jmp_buf	sendabort;

static sigtype
abortsend(int sig)
{

	mflag = 0;
	abrtflag = 0;
	printf("\nsend aborted\nwaiting for remote to finish abort\n");
	(void) fflush(stdout);
	longjmp(sendabort, 1);
}

void secure_error(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	putc('\n', stderr);
}

#define HASHBYTES 1024

void sendrequest(char *cmd, char *local, char *remote, int printnames)
{
	struct stat st;
	struct timeval start, stop;
	register int c, d;
	FILE *volatile fin, *volatile dout = 0;
	int (*volatile closefunc)();
	volatile sig_t oldintr, oldintp;
	volatile long bytes = 0, hashbytes = HASHBYTES;
	char *volatile lmode;
	unsigned char buf[FTP_BUFSIZ], *bufp;

	if (verbose && printnames) {
		if (local && *local != '-')
			printf("local: %s ", local);
		if (remote)
			printf("remote: %s\n", remote);
	}
	if (proxy) {
		proxtrans(cmd, local, remote);
		return;
	}
	if (curtype != type)
		changetype(type, 0);
	closefunc = NULL;
	oldintr = NULL;
	oldintp = NULL;
	lmode = "w";
	if (setjmp(sendabort)) {
		while (cpend) {
			(void) getreply(0);
		}
		if (data != INVALID_SOCKET) {
			(void) closesocket(data);
			data = INVALID_SOCKET;
		}
		if (oldintr)
			(void) signal(SIGINT,oldintr);
#ifdef SIGPIPE
		if (oldintp)
			(void) signal(SIGPIPE,oldintp);
#endif
		code = -1;
		return;
	}
	oldintr = signal(SIGINT, abortsend);
	if (strcmp(local, "-") == 0)
		fin = stdin;
	else if (*local == '|') {
#ifdef SIGPIPE
		oldintp = signal(SIGPIPE,SIG_IGN);
#endif
		fin = popen(local + 1, "r");
		if (fin == NULL) {
			perror(local + 1);
			(void) signal(SIGINT, oldintr);
#ifdef SIGPIPE
			(void) signal(SIGPIPE, oldintp);
#endif
			code = -1;
			return;
		}
		closefunc = pclose;
	} else {
#ifdef _WIN32
		if ((curtype == TYPE_I) || (curtype == TYPE_L))
			fin = fopen(local, "rb");
		else
			fin = fopen(local, "rt");
#else /* !_WIN32 */
		fin = fopen(local, "r");
#endif /* !_WIN32 */			
		if (fin == NULL) {
			fprintf(stderr, "local: %s: %s\n", local,
				strerror(errno));
			(void) signal(SIGINT, oldintr);
			code = -1;
			return;
		}
		closefunc = fclose;
		if (fstat(fileno(fin), &st) < 0 ||
		    (st.st_mode&S_IFMT) != S_IFREG) {
			fprintf(stdout, "%s: not a plain file.\n", local);
			(void) signal(SIGINT, oldintr);
			fclose(fin);
			code = -1;
			return;
		}
	}
	if (initconn()) {
		(void) signal(SIGINT, oldintr);
#ifdef SIGPIPE
		if (oldintp)
			(void) signal(SIGPIPE, oldintp);
#endif
		code = -1;
		if (closefunc != NULL)
			(*closefunc)(fin);
		return;
	}
	if (setjmp(sendabort))
		goto die;

	if (restart_point &&
	    (strcmp(cmd, "STOR") == 0 || strcmp(cmd, "APPE") == 0)) {
		if (fseek(fin, (long) restart_point, 0) < 0) {
			fprintf(stderr, "local: %s: %s\n", local,
				strerror(errno));
			restart_point = 0;
			if (closefunc != NULL)
				(*closefunc)(fin);
			return;
		}
		if (command("REST %ld", (long) restart_point)
			!= CONTINUE) {
			restart_point = 0;
			if (closefunc != NULL)
				(*closefunc)(fin);
			return;
		}
		restart_point = 0;
		lmode = "r+w";
	}
	if (remote) {
		if (command("%s %s", cmd, remote) != PRELIM) {
			(void) signal(SIGINT, oldintr);
#ifdef SIGPIPE
			if (oldintp)
				(void) signal(SIGPIPE, oldintp);
#endif
			if (closefunc != NULL)
				(*closefunc)(fin);
			return;
		}
	} else
		if (command("%s", cmd) != PRELIM) {
			(void) signal(SIGINT, oldintr);
#ifdef SIGPIPE
			if (oldintp)
				(void) signal(SIGPIPE, oldintp);
#endif
			if (closefunc != NULL)
				(*closefunc)(fin);
			return;
		}
	dout = dataconn(lmode);
	if (dout == NULL)
		goto die;
	(void) gettimeofday(&start, (struct timezone *)0);
#ifdef SIGPIPE
	oldintp = signal(SIGPIPE, SIG_IGN);
#endif
	switch (curtype) {

	case TYPE_I:
	case TYPE_L:
		errno = d = 0;
		while ((c = read(fileno(fin), buf, sizeof (buf))) > 0) {
			bytes += c;
			for (bufp = buf; c > 0; c -= d, bufp += d)
				if ((d = secure_write(fileno(dout), bufp, 
						      (unsigned int) c)) <= 0)
					break;
			if (hash) {
				while (bytes >= hashbytes) {
					(void) putchar('#');
					hashbytes += HASHBYTES;
				}
				(void) fflush(stdout);
			}
			if (d <= 0 ) 
  break;
		}
		if (hash && bytes > 0) {
			if (bytes < HASHBYTES)
				(void) putchar('#');
			(void) putchar('\n');
			(void) fflush(stdout);
		}
		if (c < 0)
			fprintf(stderr, "local: %s: %s\n", local,
				strerror(errno));
		if (d < 0 || (d = secure_flush(fileno(dout))) < 0) {
			if (d == -1 && errno != EPIPE) 
				perror("netout");
			bytes = -1;
		}
		break;

	case TYPE_A:
		while ((c = getc(fin)) != EOF) {
			if (c == '\n') {
				while (hash && (bytes >= hashbytes)) {
					(void) putchar('#');
					(void) fflush(stdout);
					hashbytes += HASHBYTES;
				}
				if (ferror(dout) ||
				    secure_putc('\r', dout) < 0)
					break;
				bytes++;
			}
			if (secure_putc(c, dout) < 0)
				break;
			bytes++;
	/*		if (c == '\r') {			  	*/
	/*		(void)	putc('\0', dout);   this violates rfc */
	/*			bytes++;				*/
	/*		}                          			*/	
		}
		if (hash) {
			if (bytes < hashbytes)
				(void) putchar('#');
			(void) putchar('\n');
			(void) fflush(stdout);
		}
		if (ferror(fin))
			fprintf(stderr, "local: %s: %s\n", local,
				strerror(errno));
		d = 0;
		if (ferror(dout) || (d = secure_flush(fileno(dout))) < 0) {
			if ((ferror(dout) || d == -1) && errno != EPIPE)
				perror("netout");
			bytes = -1;
		}
		break;
	}
	(void) gettimeofday(&stop, (struct timezone *)0);
	if (closefunc != NULL)
		(*closefunc)(fin);
	(void) FCLOSE_SOCKET(dout);
	dout = NULL;
	(void) getreply(0);
	(void) signal(SIGINT, oldintr);
#ifdef SIGPIPE
	if (oldintp)
		(void) signal(SIGPIPE, oldintp);
#endif
	if (bytes > 0)
		ptransfer("sent", bytes, &start, &stop);
	return;
die:
	(void) gettimeofday(&stop, (struct timezone *)0);
	(void) signal(SIGINT, oldintr);
#ifdef SIGPIPE
	if (oldintp)
		(void) signal(SIGPIPE, oldintp);
#endif
	if (!cpend) {
		code = -1;
		return;
	}
	if (data != INVALID_SOCKET) {
		(void) closesocket(data);
		data = INVALID_SOCKET;
	}
	if (dout) {
		(void) FCLOSE_SOCKET(dout);
		dout = NULL;
	}
	(void) getreply(0);
	code = -1;
	if (closefunc != NULL && fin != NULL)
		(*closefunc)(fin);
	if (bytes > 0)
		ptransfer("sent", bytes, &start, &stop);
}

jmp_buf	recvabort;

static sigtype
abortrecv(int sig)
{

	mflag = 0;
	abrtflag = 0;
	printf("\nreceive aborted\nwaiting for remote to finish abort\n");
	(void) fflush(stdout);
	longjmp(recvabort, 1);
}

void recvrequest(char *cmd, char *volatile local, char *remote, char *lmode,
		 int printnames, int fnameonly)
{
	FILE *volatile fout, *volatile din = 0, *popen();
	int (*volatile closefunc)(), pclose(), fclose();
	volatile sig_t oldintr, oldintp;
	volatile int is_retr, tcrflag, bare_lfs = 0;
	static unsigned int bufsize;
	static char *buf;
	unsigned int blksize;
	volatile long bytes = 0, hashbytes = HASHBYTES;
	register int c, d;
	struct timeval start, stop;
#ifndef NOSTBLKSIZE
	struct stat st;
#endif
	off_t lseek();

	is_retr = strcmp(cmd, "RETR") == 0;
	if (is_retr && verbose && printnames) {
		if (local && *local != '-')
			printf("local: %s ", local);
		if (remote)
			printf("remote: %s\n", remote);
	}
	if (proxy && is_retr) {
		proxtrans(cmd, local, remote);
		return;
	}
	closefunc = NULL;
	oldintr = NULL;
	oldintp = NULL;
	tcrflag = !crflag && is_retr;
	if (setjmp(recvabort)) {
		while (cpend) {
			(void) getreply(0);
		}
		if (data != INVALID_SOCKET) {
			(void) closesocket(data);
			data = INVALID_SOCKET;
		}
		if (oldintr)
			(void) signal(SIGINT, oldintr);
		code = -1;
		return;
	}
	oldintr = signal(SIGINT, abortrecv);
	if (fnameonly || (strcmp(local, "-") && *local != '|')) {
		if (access(local, 2) < 0) {
			char *dir = strrchr(local, '/');

			if (errno != ENOENT && errno != EACCES) {
				fprintf(stderr, "local: %s: %s\n", local,
					strerror(errno));
				(void) signal(SIGINT, oldintr);
				code = -1;
				return;
			}
			if (dir != NULL)
				*dir = 0;
			d = access(dir ? local : ".", 2);
			if (dir != NULL)
				*dir = '/';
			if (d < 0) {
				fprintf(stderr, "local: %s: %s\n", local,
					strerror(errno));
				(void) signal(SIGINT, oldintr);
				code = -1;
				return;
			}
			if (!runique && errno == EACCES &&
			    chmod(local, 0600) < 0) {
				fprintf(stderr, "local: %s: %s\n", local,
					strerror(errno));
				(void) signal(SIGINT, oldintr);
				(void) signal(SIGINT, oldintr);
				code = -1;
				return;
			}
			if (runique && errno == EACCES &&
			   (local = gunique(local)) == NULL) {
				(void) signal(SIGINT, oldintr);
				code = -1;
				return;
			}
		}
		else if (runique && (local = gunique(local)) == NULL) {
			(void) signal(SIGINT, oldintr);
			code = -1;
			return;
		}
	}
	if (!is_retr) {
		if (curtype != TYPE_A)
			changetype(TYPE_A, 0);
	} else if (curtype != type)
		changetype(type, 0);
	if (initconn()) {
		(void) signal(SIGINT, oldintr);
		code = -1;
		return;
	}
	if (setjmp(recvabort))
		goto die;
	if (is_retr && restart_point &&
	    command("REST %ld", (long) restart_point) != CONTINUE)
		return;
	if (remote) {
		if (command("%s %s", cmd, remote) != PRELIM) {
			(void) signal(SIGINT, oldintr);
			return;
		}
	} else {
		if (command("%s", cmd) != PRELIM) {
			(void) signal(SIGINT, oldintr);
			return;
		}
	}
	din = dataconn("r");
	if (din == NULL)
		goto die;
	if (strcmp(local, "-") == 0 && !fnameonly)
		fout = stdout;
	else if (*local == '|' && !fnameonly) {
#ifdef SIGPIPE
		oldintp = signal(SIGPIPE, SIG_IGN);
#endif
		fout = popen(local + 1, "w");
		if (fout == NULL) {
			perror(local+1);
			goto die;
		}
		closefunc = pclose;
	} else {
#ifdef _WIN32
		int old_fmode = _fmode;

		if ((curtype == TYPE_I) || (curtype == TYPE_L))
			_fmode = _O_BINARY;
#endif /* _WIN32 */
		fout = fopen(local, lmode);
#ifdef _WIN32
		_fmode = old_fmode;
#endif
		if (fout == NULL) {
			fprintf(stderr, "local: %s: %s\n", local,
				strerror(errno));
			goto die;
		}
		closefunc = fclose;
	}
	blksize = FTP_BUFSIZ;
#ifndef NOSTBLKSIZE
	if (fstat(fileno(fout), &st) == 0 && st.st_blksize != 0)
		blksize = st.st_blksize;
#endif
	if (blksize > bufsize) {
		if (buf)
			(void) free(buf);
		buf = (char *)malloc((unsigned)blksize);
		if (buf == NULL) {
			perror("malloc");
			bufsize = 0;
			goto die;
		}
		bufsize = blksize;
	}
	(void) gettimeofday(&start, (struct timezone *)0);
	switch (curtype) {

	case TYPE_I:
	case TYPE_L:
		if (restart_point &&
		    lseek(fileno(fout), (long) restart_point, L_SET) < 0) {
			fprintf(stderr, "local: %s: %s\n", local,
				strerror(errno));
			if (closefunc != NULL)
				(*closefunc)(fout);
			return;
		}
		errno = d = 0;
		while ((c = secure_read(fileno(din), buf, bufsize)) > 0) {
		        d = write(fileno(fout), buf,(unsigned int) c);
			if (d != c)
				break;
			bytes += c;
			if (hash) {
				while (bytes >= hashbytes) {
					(void) putchar('#');
					hashbytes += HASHBYTES;
				}
				(void) fflush(stdout);
			}
		}
		if (hash && bytes > 0) {
			if (bytes < HASHBYTES)
				(void) putchar('#');
			(void) putchar('\n');
			(void) fflush(stdout);
		}
		if (c < 0) {
			if (c == -1 && errno != EPIPE)
				perror("netin");
			bytes = -1;
		}
		if (d < c) {
			if (d < 0)
				fprintf(stderr, "local: %s: %s\n", local,
					strerror(errno));
			else
				fprintf(stderr, "%s: short write\n", local);
		}
		break;

	case TYPE_A:
		if (restart_point) {
			register int i, n, ch;

			if (fseek(fout, 0L, L_SET) < 0)
				goto done;
			n = restart_point;
			for (i = 0; i++ < n;) {
				if ((ch = getc(fout)) == EOF)
					goto done;
				if (ch == '\n')
					i++;
			}
			if (fseek(fout, 0L, L_INCR) < 0) {
done:
				fprintf(stderr, "local: %s: %s\n", local,
					strerror(errno));
				if (closefunc != NULL)
					(*closefunc)(fout);
				return;
			}
		}
		while ((c = secure_getc(din)) >= 0) {
			if (c == '\n')
				bare_lfs++;
			while (c == '\r') {
				while (hash && (bytes >= hashbytes)) {
					(void) putchar('#');
					(void) fflush(stdout);
					hashbytes += HASHBYTES;
				}
				bytes++;
				if ((c = secure_getc(din)) != '\n' || tcrflag) {
					if (ferror(fout))
						goto break2;
					(void) putc('\r', fout);
					if (c == '\0') {
						bytes++;
						goto contin2;
					}
				}
			}
			if (c < 0) break;
			(void) putc(c, fout);
			bytes++;
	contin2:	;
		}
break2:
		if (bare_lfs) {
			printf("WARNING! %d bare linefeeds received in ASCII mode\n", bare_lfs);
			printf("File may not have transferred correctly.\n");
		}
		if (hash) {
			if (bytes < hashbytes)
				(void) putchar('#');
			(void) putchar('\n');
			(void) fflush(stdout);
		}
		if (ferror(din)) {
			if (errno != EPIPE)
				perror("netin");
			bytes = -1;
		}
		if (ferror(fout) || c == -2) {
		    if (c != -2)
			fprintf(stderr, "local: %s: %s\n", local,
				strerror(errno));
			bytes = -1;
		}
		break;
	}
	if (closefunc != NULL)
		(*closefunc)(fout);
	(void) signal(SIGINT, oldintr);
#ifdef SIGPIPE
	if (oldintp)
		(void) signal(SIGPIPE, oldintp);
#endif
	(void) gettimeofday(&stop, (struct timezone *)0);
	(void) FCLOSE_SOCKET(din);
	din = NULL;
	(void) getreply(0);
	if (bytes > 0 && is_retr)
		ptransfer("received", bytes, &start, &stop);
	return;
die:

/* abort using RFC959 recommended IP,SYNC sequence  */

	(void) gettimeofday(&stop, (struct timezone *)0);
#ifdef SIGPIPE
	if (oldintp)
		(void) signal(SIGPIPE, oldintr);
#endif
	(void) signal(SIGINT, SIG_IGN);
	if (!cpend) {
		code = -1;
		(void) signal(SIGINT, oldintr);
		return;
	}

	abort_remote(din);
	code = -1;
	if (data != INVALID_SOCKET) {
		(void) closesocket(data);
		data = INVALID_SOCKET;
	}
	if (closefunc != NULL && fout != NULL)
		(*closefunc)(fout);
	if (din) {
		(void) FCLOSE_SOCKET(din);
		din = NULL;
	}
	if (bytes > 0)
		ptransfer("received", bytes, &start, &stop);
	(void) signal(SIGINT, oldintr);
}

/*
 * Need to start a listen on the data channel before we send the command,
 * otherwise the server's connect may fail.
 */
static int initconn()
{
	register char *p, *a;
	int result, tmpno = 0;
	socklen_t len;
	int on = 1;
#ifndef NO_PASSIVE_MODE
	int a1,a2,a3,a4,p1,p2;

	if (passivemode) {
		data = socket(AF_INET, SOCK_STREAM, 0);
		if (data == INVALID_SOCKET) {
			PERROR_SOCKET("ftp: socket");
			return(1);
		}
		if (options & SO_DEBUG &&
		    setsockopt(data, SOL_SOCKET, SO_DEBUG, (char *)&on, sizeof (on)) == SOCKET_ERROR)
			PERROR_SOCKET("ftp: setsockopt (ignored)");
		if (command("PASV") != COMPLETE) {
			printf("Passive mode refused.  Turning off passive mode.\n");
			passivemode = 0;
			return initconn();
		}

/*
 * What we've got at this point is a string of comma separated
 * one-byte unsigned integer values, separated by commas.
 * The first four are the an IP address. The fifth is the MSB
 * of the port number, the sixth is the LSB. From that we'll
 * prepare a sockaddr_in.
 */

		if (sscanf(pasv,"%d,%d,%d,%d,%d,%d",&a1,&a2,&a3,&a4,&p1,&p2) != 6) {
			printf("Passive mode address scan failure. Shouldn't happen!\n");
			return(1);
		};

		data_addr.sin_family = AF_INET;
		data_addr.sin_addr.s_addr = htonl((a1<<24)|(a2<<16)|(a3<<8)|a4);
		data_addr.sin_port = htons((p1<<8)|p2);

		if (connect(data, (struct sockaddr *) &data_addr, sizeof(data_addr)) == SOCKET_ERROR) {
			PERROR_SOCKET("ftp: connect");
			return(1);
		}
#ifdef IP_TOS
#ifdef IPTOS_THROUGHPUT
	on = IPTOS_THROUGHPUT;
	if (setsockopt(data, IPPROTO_IP, IP_TOS, (char *)&on, sizeof(int)) == SOCKET_ERROR)
		PERROR_SOCKET("ftp: setsockopt TOS (ignored)");
#endif
#endif
		hisdataaddr = data_addr;
		return(0);
	}
#endif

noport:
	data_addr = myctladdr;
	if (sendport)
		data_addr.sin_port = 0;	/* let system pick one */ 
	if (data != INVALID_SOCKET)
		(void) closesocket(data);
	data = socket(AF_INET, SOCK_STREAM, 0);
	if (data == INVALID_SOCKET) {
		PERROR_SOCKET("ftp: socket");
		if (tmpno)
			sendport = 1;
		return (1);
	}
	if (!sendport)
		if (setsockopt(data, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof (on)) == SOCKET_ERROR) {
			PERROR_SOCKET("ftp: setsockopt (reuse address)");
			goto bad;
		}
	if (bind(data, (struct sockaddr *)&data_addr, sizeof (data_addr)) == SOCKET_ERROR) {
		PERROR_SOCKET("ftp: bind");
		goto bad;
	}
	if (options & SO_DEBUG &&
	    setsockopt(data, SOL_SOCKET, SO_DEBUG, (char *)&on, sizeof (on)) == SOCKET_ERROR)
		PERROR_SOCKET("ftp: setsockopt (ignored)");
	len = sizeof (data_addr);
	if (getsockname(data, (struct sockaddr *)&data_addr, &len) == SOCKET_ERROR) {
		PERROR_SOCKET("ftp: getsockname");
		goto bad;
	}
	if (listen(data, 1) == SOCKET_ERROR)
		PERROR_SOCKET("ftp: listen");
	if (sendport) {
		a = (char *)&data_addr.sin_addr;
		p = (char *)&data_addr.sin_port;
#define	UC(b)	(((int)b)&0xff)
		result =
		    command("PORT %d,%d,%d,%d,%d,%d",
		      UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
		      UC(p[0]), UC(p[1]));
		if (result == ERROR && sendport == -1) {
			sendport = 0;
			tmpno = 1;
			goto noport;
		}
		return (result != COMPLETE);
	}
	if (tmpno)
		sendport = 1;
#ifdef IP_TOS
#ifdef IPTOS_THROUGHPUT
	on = IPTOS_THROUGHPUT;
	if (setsockopt(data, IPPROTO_IP, IP_TOS, (char *)&on, sizeof(int)) == SOCKET_ERROR)
		PERROR_SOCKET("ftp: setsockopt TOS (ignored)");
#endif
#endif
	return (0);
bad:
	(void) closesocket(data), data = INVALID_SOCKET;
	if (tmpno)
		sendport = 1;
	return (1);
}

FILE *
dataconn(char *lmode)
{
	int s;
	socklen_t fromlen = sizeof (hisdataaddr);
#ifdef IP_TOS
#ifdef IPTOS_LOWDELAY
        int tos;
#endif
#endif

#ifndef NO_PASSIVE_MODE
	if (passivemode)
		return (FDOPEN_SOCKET(data, lmode));
#endif
	s = accept(data, (struct sockaddr *) &hisdataaddr, &fromlen);
	if (s == INVALID_SOCKET) {
		PERROR_SOCKET("ftp: accept");
		(void) closesocket(data), data = INVALID_SOCKET;
		return (NULL);
	}
	(void) closesocket(data);
	data = s;
#ifdef IP_TOS
#ifdef IPTOS_THROUGHPUT
	tos = IPTOS_THROUGHPUT;
	if (setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int)) == SOCKET_ERROR)
		PERROR_SOCKET("ftp: setsockopt TOS (ignored)");
#endif
#endif
	return (FDOPEN_SOCKET(data, lmode));
}

static void ptransfer(char *direction, long bytes,
		      struct timeval *t0, struct timeval *t1)
{
	struct timeval td;
	float s, kbs;

	if (verbose) {
		tvsub(&td, t1, t0);
		s = td.tv_sec + (td.tv_usec / 1000000.);
#define	nz(x)	((x) == 0 ? 1 : (x))
		kbs = (bytes / nz(s))/1024.0;
		printf("%ld bytes %s in %.2g seconds (%.2g Kbytes/s)\n",
		    bytes, direction, s, kbs);
	}
}

/*tvadd(tsum, t0)
	struct timeval *tsum, *t0;
{

	tsum->tv_sec += t0->tv_sec;
	tsum->tv_usec += t0->tv_usec;
	if (tsum->tv_usec > 1000000)
		tsum->tv_sec++, tsum->tv_usec -= 1000000;
} */

static void tvsub(struct timeval *tdiff, struct timeval *t1,
		  struct timeval *t0)
{

	tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff->tv_usec = t1->tv_usec - t0->tv_usec;
	if (tdiff->tv_usec < 0)
		tdiff->tv_sec--, tdiff->tv_usec += 1000000;
}

static sigtype
psabort(int sig)
{
	abrtflag++;
}

void pswitch(int flag)
{
	sig_t oldintr;
	static struct comvars {
		int connect;
		char name[MAXHOSTNAMELEN];
		struct sockaddr_in mctl;
		struct sockaddr_in hctl;
		FILE *in;
		FILE *out;
		int tpe;
		int curtpe;
		int cpnd;
		int sunqe;
		int runqe;
		int mcse;
		int ntflg;
		char nti[17];
		char nto[17];
		int mapflg;
		char mi[MAXPATHLEN];
		char mo[MAXPATHLEN];
		char *authtype;
		int clvl;
	        int dlvl;
#ifdef KRB5_KRB4_COMPAT
		C_Block session;
		Key_schedule schedule;
#endif /* KRB5_KRB4_COMPAT */
	} proxstruct, tmpstruct;
	struct comvars *ip, *op;

	abrtflag = 0;
	oldintr = signal(SIGINT, psabort);
	if (flag) {
		if (proxy)
			return;
		ip = &tmpstruct;
		op = &proxstruct;
		proxy++;
	} else {
		if (!proxy)
			return;
		ip = &proxstruct;
		op = &tmpstruct;
		proxy = 0;
	}
	ip->connect = connected;
	connected = op->connect;
	if (hostname) {
		(void) strncpy(ip->name, hostname, sizeof(ip->name) - 1);
		ip->name[strlen(ip->name)] = '\0';
	} else
		ip->name[0] = 0;
	hostname = op->name;
	ip->hctl = hisctladdr;
	hisctladdr = op->hctl;
	ip->mctl = myctladdr;
	myctladdr = op->mctl;
	ip->in = cin;
	cin = op->in;
	ip->out = cout;
	cout = op->out;
	ip->tpe = type;
	type = op->tpe;
	ip->curtpe = curtype;
	curtype = op->curtpe;
	ip->cpnd = cpend;
	cpend = op->cpnd;
	ip->sunqe = sunique;
	sunique = op->sunqe;
	ip->runqe = runique;
	runique = op->runqe;
	ip->mcse = mcase;
	mcase = op->mcse;
	ip->ntflg = ntflag;
	ntflag = op->ntflg;
	(void) strncpy(ip->nti, ntin, sizeof(ip->nti) - 1);
	(ip->nti)[strlen(ip->nti)] = '\0';
	(void) strncpy(ntin, op->nti, sizeof(ntin) - 1);
	ntin[sizeof(ntin) - 1] = '\0';
	(void) strncpy(ip->nto, ntout, sizeof(ip->nto) - 1);
	(ip->nto)[strlen(ip->nto)] = '\0';
	(void) strncpy(ntout, op->nto, sizeof(ntout) - 1);
	ntout[sizeof(ntout) - 1] = '\0';
	ip->mapflg = mapflag;
	mapflag = op->mapflg;
	(void) strncpy(ip->mi, mapin, MAXPATHLEN - 1);
	(ip->mi)[strlen(ip->mi)] = '\0';
	(void) strncpy(mapin, op->mi, sizeof(mapin) - 1);
	mapin[sizeof(mapin) - 1] = '\0';
	(void) strncpy(ip->mo, mapout, MAXPATHLEN - 1);
	(ip->mo)[strlen(ip->mo)] = '\0';
	(void) strncpy(mapout, op->mo, sizeof(mapout) - 1);
	mapout[sizeof(mapout) - 1] = '\0';
	ip->authtype = auth_type;
	auth_type = op->authtype;
	ip->clvl = clevel;
	clevel = op->clvl;
	ip->dlvl = dlevel;
	dlevel = op->dlvl;
	if (!clevel)
	     clevel = PROT_C;
	if (!dlevel)
	     dlevel = PROT_C;
#ifdef KRB5_KRB4_COMPAT
	memcpy(ip->session, cred.session, sizeof(cred.session));
	memcpy(cred.session, op->session, sizeof(cred.session));
	memcpy(ip->schedule, schedule, sizeof(schedule));
	memcpy(schedule, op->schedule, sizeof(schedule));
#endif /* KRB5_KRB4_COMPAT */
	(void) signal(SIGINT, oldintr);
	if (abrtflag) {
		abrtflag = 0;
		if (oldintr)
			(*oldintr)(SIGINT);
	}
}

int ptabflg;

static sigtype
abortpt(int sig)
{
	printf("\n");
	(void) fflush(stdout);
	ptabflg++;
	mflag = 0;
	abrtflag = 0;
	longjmp(ptabort, 1);
}

static void
proxtrans(char *cmd, char *local, char *remote)
{
	volatile sig_t oldintr;
	volatile int secndflag = 0;
	int prox_type, nfnd;
	char *volatile cmd2;
	 fd_set mask;

	if (strcmp(cmd, "RETR"))
		cmd2 = "RETR";
	else
		cmd2 = runique ? "STOU" : "STOR";
	if ((prox_type = type) == 0) {
		if (unix_server && unix_proxy)
			prox_type = TYPE_I;
		else
			prox_type = TYPE_A;
	}
	if (curtype != prox_type)
		changetype(prox_type, 1);
	if (command("PASV") != COMPLETE) {
		printf("proxy server does not support third party transfers.\n");
		return;
	}
	pswitch(0);
	if (!connected) {
		printf("No primary connection\n");
		pswitch(1);
		code = -1;
		return;
	}
	if (curtype != prox_type)
		changetype(prox_type, 1);
	if (command("PORT %s", pasv) != COMPLETE) {
		pswitch(1);
		return;
	}
	if (setjmp(ptabort))
		goto die;
	oldintr = signal(SIGINT, abortpt);
	if (command("%s %s", cmd, remote) != PRELIM) {
		(void) signal(SIGINT, oldintr);
		pswitch(1);
		return;
	}
	sleep(2);
	pswitch(1);
	secndflag++;
	if (command("%s %s", cmd2, local) != PRELIM)
		goto die;
	ptflag++;
	(void) getreply(0);
	pswitch(0);
	(void) getreply(0);
	(void) signal(SIGINT, oldintr);
	pswitch(1);
	ptflag = 0;
	printf("local: %s remote: %s\n", local, remote);
	return;
die:
	(void) signal(SIGINT, SIG_IGN);
	ptflag = 0;
	if (strcmp(cmd, "RETR") && !proxy)
		pswitch(1);
	else if (!strcmp(cmd, "RETR") && proxy)
		pswitch(0);
	if (!cpend && !secndflag) {  /* only here if cmd = "STOR" (proxy=1) */
		if (command("%s %s", cmd2, local) != PRELIM) {
			pswitch(0);
			if (cpend)
				abort_remote((FILE *) NULL);
		}
		pswitch(1);
		if (ptabflg)
			code = -1;
		(void) signal(SIGINT, oldintr);
		return;
	}
	if (cpend)
		abort_remote((FILE *) NULL);
	pswitch(!proxy);
	if (!cpend && !secndflag) {  /* only if cmd = "RETR" (proxy=1) */
		if (command("%s %s", cmd2, local) != PRELIM) {
			pswitch(0);
			if (cpend)
				abort_remote((FILE *) NULL);
			pswitch(1);
			if (ptabflg)
				code = -1;
			(void) signal(SIGINT, oldintr);
			return;
		}
	}
	if (cpend)
		abort_remote((FILE *) NULL);
	pswitch(!proxy);
	if (cpend) {
		FD_ZERO(&mask);
		FD_SET(SOCKETNO(fileno(cin)), &mask);
		if ((nfnd = empty(&mask, 10)) <= 0) {
			if (nfnd < 0) {
				perror("abort");
			}
			if (ptabflg)
				code = -1;
			lostpeer();
		}
		(void) getreply(0);
		(void) getreply(0);
	}
	if (proxy)
		pswitch(0);
	pswitch(1);
	if (ptabflg)
		code = -1;
	(void) signal(SIGINT, oldintr);
}

void reset()
{
   fd_set mask;
	int nfnd = 1;

	FD_ZERO(&mask);
	while (nfnd > 0) {
		FD_SET(SOCKETNO(fileno(cin)), &mask);
		if ((nfnd = empty(&mask,0)) < 0) {
			perror("reset");
			code = -1;
			lostpeer();
		}
		else if (nfnd) {
			(void) getreply(0);
		}
	}
}

static char *
gunique(char *local)
{
	static char new[MAXPATHLEN];
	char *cp = strrchr(local, '/');
	int d, count=0;
	char ext = '1';

	if (cp)
		*cp = '\0';
	d = access(cp ? local : ".", 2);
	if (cp)
		*cp = '/';
	if (d < 0) {
		fprintf(stderr, "local: %s: %s\n", local, strerror(errno));
		return((char *) 0);
	}
	(void) strncpy(new, local, sizeof(new) - 3);
	new[sizeof(new) - 1] = '\0';
	cp = new + strlen(new);
	*cp++ = '.';
	while (!d) {
		if (++count == 100) {
			printf("runique: can't find unique file name.\n");
			return((char *) 0);
		}
		*cp++ = ext;
		*cp = '\0';
		if (ext == '9')
			ext = '0';
		else
			ext++;
		if ((d = access(new, 0)) < 0)
			break;
		if (ext != '0')
			cp--;
		else if (*(cp - 2) == '.')
			*(cp - 1) = '1';
		else {
			*(cp - 2) = *(cp - 2) + 1;
			cp--;
		}
	}
	return(new);
}

#ifdef KRB5_KRB4_COMPAT
char realm[REALM_SZ + 1];
#endif /* KRB5_KRB4_COMPAT */

#ifdef GSSAPI
struct {
    gss_OID mech_type;
    char *service_name;
} gss_trials[] = {
    { GSS_C_NO_OID, "ftp" },
    { GSS_C_NO_OID, "host" },
};
int n_gss_trials = sizeof(gss_trials)/sizeof(gss_trials[0]);
#endif /* GSSAPI */

int do_auth()
{
	int oldverbose = verbose;
#ifdef KRB5_KRB4_COMPAT
	char *service, inst[INST_SZ];
	KRB4_32 cksum, checksum = getpid();
#endif /* KRB5_KRB4_COMPAT */
#if defined(KRB5_KRB4_COMPAT) || defined(GSSAPI)
	u_char out_buf[FTP_BUFSIZ];
	int i;
#endif /* KRB5_KRB4_COMPAT */

	if (auth_type) return(1);	/* auth already succeeded */

	/* Other auth types go here ... */

#ifdef GSSAPI
	if (command("AUTH %s", "GSSAPI") == CONTINUE) {
	  OM_uint32 maj_stat, min_stat, dummy_stat;
	  gss_name_t target_name;
	  gss_buffer_desc send_tok, recv_tok, *token_ptr;
	  char stbuf[FTP_BUFSIZ];
	  int comcode, trial;
	  struct gss_channel_bindings_struct chan;
	  chan.initiator_addrtype = GSS_C_AF_INET; /* OM_uint32  */ 
	  chan.initiator_address.length = 4;
	  chan.initiator_address.value = &myctladdr.sin_addr.s_addr;
	  chan.acceptor_addrtype = GSS_C_AF_INET; /* OM_uint32 */
	  chan.acceptor_address.length = 4;
	  chan.acceptor_address.value = &hisctladdr.sin_addr.s_addr;
	  chan.application_data.length = 0;
	  chan.application_data.value = 0;

	  if (verbose)
	    printf("GSSAPI accepted as authentication type\n");
	  
	  /* blob from gss-client */
	  
	  for (trial = 0; trial < n_gss_trials; trial++) {
	    /* ftp@hostname first, the host@hostname */
	    /* the V5 GSSAPI binding canonicalizes this for us... */
	    sprintf(stbuf, "%s@%s", gss_trials[trial].service_name, hostname);
	    if (debug)
	      fprintf(stderr, "Trying to authenticate to <%s>\n", stbuf);

	    send_tok.value = stbuf;
	    send_tok.length = strlen(stbuf) + 1;
	    maj_stat = gss_import_name(&min_stat, &send_tok,
				       gss_nt_service_name, &target_name);
	    
	    if (maj_stat != GSS_S_COMPLETE) {
		    user_gss_error(maj_stat, min_stat, "parsing name");
		    secure_error("name parsed <%s>\n", stbuf);
		    continue;
	    }

	    token_ptr = GSS_C_NO_BUFFER;
	    gcontext = GSS_C_NO_CONTEXT; /* structure copy */
	    
	    do {
	      if (debug)
		fprintf(stderr, "calling gss_init_sec_context\n");
	      maj_stat =
		gss_init_sec_context(&min_stat,
				     GSS_C_NO_CREDENTIAL,
				     &gcontext,
				     target_name,
				     (gss_OID_desc *)gss_trials[trial].mech_type,
				     GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG |
				       (forward ? GSS_C_DELEG_FLAG : 
					(unsigned) 0),
				     0,
				     &chan,	/* channel bindings */
				     token_ptr,
				     NULL,	/* ignore mech type */
				     &send_tok,
				     NULL,	/* ignore ret_flags */
				     NULL);	/* ignore time_rec */
	      

	      if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED){
		if (trial == n_gss_trials-1)
		  user_gss_error(maj_stat, min_stat, "initializing context");
		/* could just be that we missed on the service name */
		goto outer_loop;
	      }
	    
	      if (send_tok.length != 0) {
		int len = send_tok.length;
		reply_parse = "ADAT="; /* for command() later */
		oldverbose = verbose;
		verbose = (trial == n_gss_trials-1)?0:-1;
		kerror = radix_encode(send_tok.value, out_buf, &len, 0);
		gss_release_buffer(&dummy_stat, &send_tok);
		if (kerror)  {
		  fprintf(stderr, "Base 64 encoding failed: %s\n",
			  radix_error(kerror));
		} else if ((comcode = command("ADAT %s", out_buf))!=COMPLETE
			   && comcode != 3 /* (335) */) {
		    if (trial == n_gss_trials-1) {
			fprintf(stderr, "GSSAPI ADAT failed\n");
			/* force out of loop */
			maj_stat = GSS_S_FAILURE;
		    }
		    /* backoff to the v1 gssapi is still possible.  Send
		       a new AUTH command.  If that fails, terminate the
		       loop */
		    if (command("AUTH %s", "GSSAPI") != CONTINUE) {
			fprintf(stderr,
				"GSSAPI ADAT failed, AUTH restart failed\n");
			/* force out of loop */
			maj_stat = GSS_S_FAILURE;
		    }
		    goto outer_loop;
		} else if (!reply_parse) {
		  fprintf(stderr,
			  "No authentication data received from server\n");
		  if (maj_stat == GSS_S_COMPLETE) {
		    fprintf(stderr, "...but no more was needed\n");
		    goto gss_complete_loop;
		  } else {
		    user_gss_error(maj_stat, min_stat, "no reply, huh?");
		    goto gss_complete_loop;
		  }
		} else if ((kerror = radix_encode((unsigned char *)reply_parse,
						  out_buf,&i,1))) {
		  fprintf(stderr, "Base 64 decoding failed: %s\n",
			  radix_error(kerror));
		} else {
		  /* everything worked */
		  token_ptr = &recv_tok;
		  recv_tok.value = out_buf;
		  recv_tok.length = i;
		  continue;
		}

		/* get out of loop clean */
	      gss_complete_loop:
		trial = n_gss_trials-1;
		goto outer_loop;
	      }
	    } while (maj_stat == GSS_S_CONTINUE_NEEDED);
    outer_loop:
	    gss_release_name(&dummy_stat, &target_name);
	    if (maj_stat == GSS_S_COMPLETE)
	        break;
	  }
	  verbose = oldverbose;
	  if (maj_stat == GSS_S_COMPLETE) {
	    printf("GSSAPI authentication succeeded\n");
	    reply_parse = NULL;
	    auth_type = "GSSAPI";
	    return(1);
	  } else {
	    fprintf(stderr, "GSSAPI authentication failed\n");
	    verbose = oldverbose;
	    reply_parse = NULL;
	  }
	}
#endif /* GSSAPI */
#ifdef KRB5_KRB4_COMPAT
	if (command("AUTH %s", "KERBEROS_V4") == CONTINUE) {
	    if (verbose)
		printf("%s accepted as authentication type\n", "KERBEROS_V4");

	    strncpy(inst, (char *) krb_get_phost(hostname), sizeof(inst) - 1);
	    inst[sizeof(inst) - 1] = '\0';
	    if (realm[0] == '\0')
	    	strncpy(realm, (char *) krb_realmofhost(hostname), sizeof(realm) - 1);
	    realm[sizeof(realm) - 1] = '\0';
	    if ((kerror = krb_mk_req(&ticket, service = "ftp",
					inst, realm, checksum))
		&& (kerror != KDC_PR_UNKNOWN ||
	        (kerror = krb_mk_req(&ticket, service = "rcmd",
					inst, realm, checksum))))
			fprintf(stderr, "Kerberos V4 krb_mk_req failed: %s\n",
					krb_get_err_text(kerror));
	    else if ((kerror = krb_get_cred(service, inst, realm, &cred)))
			fprintf(stderr, "Kerberos V4 krb_get_cred failed: %s\n",
					krb_get_err_text(kerror));
	    else {
		key_sched(cred.session, schedule);
		reply_parse = "ADAT=";
		oldverbose = verbose;
		verbose = 0;
		i = ticket.length;
		if ((kerror = radix_encode(ticket.dat, out_buf, &i, 0)))
			fprintf(stderr, "Base 64 encoding failed: %s\n",
					radix_error(kerror));
		else if (command("ADAT %s", out_buf) != COMPLETE)
			fprintf(stderr, "Kerberos V4 authentication failed\n");
		else if (!reply_parse)
			fprintf(stderr,
			       "No authentication data received from server\n");
		else if ((kerror = radix_encode((unsigned char *)reply_parse, out_buf, &i, 1)))
			fprintf(stderr, "Base 64 decoding failed: %s\n",
					radix_error(kerror));
		else if ((kerror = krb_rd_safe(out_buf, (unsigned )i,
					       &cred.session,
					       &hisctladdr, &myctladdr, 
					       &msg_data)))
			fprintf(stderr, "Kerberos V4 krb_rd_safe failed: %s\n",
					krb_get_err_text(kerror));
		else {
		    /* fetch the (modified) checksum */
		    (void) memcpy(&cksum, msg_data.app_data, sizeof(cksum));
		    if (ntohl(cksum) == checksum + 1) {
			verbose = oldverbose;
			if (verbose)
			   printf("Kerberos V4 authentication succeeded\n");
			reply_parse = NULL;
			auth_type = "KERBEROS_V4";
			return(1);
		    } else fprintf(stderr,
				"Kerberos V4 mutual authentication failed\n");
		}
		verbose = oldverbose;
		reply_parse = NULL;
	    }
	} else	fprintf(stderr, "%s rejected as an authentication type\n",
				"KERBEROS_V4");
#endif /* KRB5_KRB4_COMPAT */

	/* Other auth types go here ... */

	return(0);
}

void
setpbsz(unsigned int size)
{
	int oldverbose;

	if (ucbuf) (void) free(ucbuf);
	actualbuf = size;
	while ((ucbuf = (unsigned char *)malloc(actualbuf)) == NULL)
		if (actualbuf)
			actualbuf >>= 2;
		else {
			perror("Error while trying to malloc PROT buffer:");
			exit(1);
		}
	oldverbose = verbose;
	verbose = 0;
	reply_parse = "PBSZ=";
	if (command("PBSZ %u", actualbuf) != COMPLETE)
		fatal("Cannot set PROT buffer size");
	if (reply_parse) {
		if ((maxbuf = (unsigned int) atol(reply_parse)) > actualbuf)
			maxbuf = actualbuf;
	} else	maxbuf = actualbuf;
	reply_parse = NULL;
	verbose = oldverbose;
}

static void abort_remote(FILE *din)
{
	char buf[FTP_BUFSIZ];
	int nfnd;
	fd_set mask;

	/*
	 * send IAC in urgent mode instead of DM because 4.3BSD places oob mark
	 * after urgent byte rather than before as is protocol now
	 */
	sprintf(buf, "%c%c%c", IAC, IP, IAC);
	if (send(SOCKETNO(fileno(cout)), buf, 3, MSG_OOB) != 3)
		PERROR_SOCKET("abort");
	putc(DM, cout);
	(void) secure_command("ABOR");
	FD_ZERO(&mask);
	FD_SET(SOCKETNO(fileno(cin)), &mask);
	if (din) { 
		FD_SET(SOCKETNO(fileno(din)), &mask);
	}
	if ((nfnd = empty(&mask, 10)) <= 0) {
		if (nfnd < 0) {
			perror("abort");
		}
		if (ptabflg)
			code = -1;
		lostpeer();
	}
	if (din && FD_ISSET(SOCKETNO(fileno(din)), &mask)) {
		/* Security: No threat associated with this read. */
		while (read(fileno(din), buf, FTP_BUFSIZ) > 0)
			/* LOOP */;
	}
	if (getreply(0) == ERROR && code == 552) {
		/* 552 needed for nic style abort */
		(void) getreply(0);
	}
	(void) getreply(0);
}

#ifdef GSSAPI
void user_gss_error(OM_uint32 maj_stat, OM_uint32 min_stat, char *s)
{
	/* a lot of work just to report the error */
	OM_uint32 gmaj_stat, gmin_stat, msg_ctx;
	gss_buffer_desc msg;
	msg_ctx = 0;
	while (!msg_ctx) {
		gmaj_stat = gss_display_status(&gmin_stat, maj_stat,
					       GSS_C_GSS_CODE,
					       GSS_C_NULL_OID,
					       &msg_ctx, &msg);
		if ((gmaj_stat == GSS_S_COMPLETE)||
		    (gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
			fprintf(stderr, "GSSAPI error major: %s\n",
				(char*)msg.value);
			(void) gss_release_buffer(&gmin_stat, &msg);
		}
		if (gmaj_stat != GSS_S_CONTINUE_NEEDED)
			break;
	}
	msg_ctx = 0;
	while (!msg_ctx) {
		gmaj_stat = gss_display_status(&gmin_stat, min_stat,
					       GSS_C_MECH_CODE,
					       GSS_C_NULL_OID,
					       &msg_ctx, &msg);
		if ((gmaj_stat == GSS_S_COMPLETE)||
		    (gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
			fprintf(stderr, "GSSAPI error minor: %s\n",
				(char*)msg.value);
			(void) gss_release_buffer(&gmin_stat, &msg);
		}
		if (gmaj_stat != GSS_S_CONTINUE_NEEDED)
			break;
	}
	fprintf(stderr, "GSSAPI error: %s\n", s);
}

void secure_gss_error(OM_uint32 maj_stat, OM_uint32 min_stat, char *s)
{
  user_gss_error(maj_stat, min_stat, s);
  return;
}
#endif /* GSSAPI */

#ifdef _WIN32

int gettimeofday(struct timeval *tv, void *tz)
{
	struct _timeb tb;
	_tzset();
	_ftime(&tb);
	if (tv) {
		tv->tv_sec = tb.time;
		tv->tv_usec = tb.millitm * 1000;
	}
#if 0
	if (tz) {
		tz->tz_minuteswest = tb.timezone;
		tz->tz_dsttime = tb.dstflag;
	}
#else
	_ASSERTE(!tz);
#endif
	return 0;
}

int fclose_socket(FILE* f)
{
	int rc = 0;
	SOCKET _s = _get_osfhandle(_fileno(f));

	rc = fclose(f);
	if (rc)
		return rc;
	if (closesocket(_s) == SOCKET_ERROR)
		return SOCKET_ERRNO;
	return 0;
}

FILE* fdopen_socket(SOCKET s, char* mode)
{
	int o_mode = 0;
	int old_fmode = _fmode;
	FILE* f = 0;

	if (strstr(mode, "a+")) o_mode |= _O_RDWR | _O_APPEND;
	if (strstr(mode, "r+")) o_mode |= _O_RDWR;
	if (strstr(mode, "w+")) o_mode |= _O_RDWR;
	if (strchr(mode, 'a')) o_mode |= _O_WRONLY | _O_APPEND;
	if (strchr(mode, 'r')) o_mode |= _O_RDONLY;
	if (strchr(mode, 'w')) o_mode |= _O_WRONLY;

	/* In theory, _open_osfhandle only takes: _O_APPEND, _O_RDONLY, _O_TEXT */

	_fmode = _O_BINARY;
	f = fdopen(_open_osfhandle(s, o_mode), mode);
	_fmode = old_fmode;

	return f;
}
#endif /* _WIN32 */
