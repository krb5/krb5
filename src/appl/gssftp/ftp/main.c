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

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1985, 1989 Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)main.c	5.18 (Berkeley) 3/1/91";
#endif /* not lint */

/*
 * FTP User Program -- Command Interface.
 */
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <signal.h>
#include "ftp_var.h"
#ifndef _WIN32
#ifndef KRB5_KRB4_COMPAT
/* krb.h gets this, and Ultrix doesn't protect vs multiple inclusion */
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pwd.h>
#endif /* !_WIN32 */

#ifdef _WIN32
#include <io.h>
#undef ERROR
#endif

#include <arpa/ftp.h>

#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <port-sockets.h>

#ifdef _WIN32
/* For SO_SYNCHRONOUS_NONALERT and SO_OPENTYPE: */
#include <mswsock.h>
#endif

#ifndef _WIN32
uid_t	getuid();
#endif

sigtype	intr (int), lostpeer (int);
extern	char *home;
char	*getlogin();
#ifdef KRB5_KRB4_COMPAT
#include <krb.h>
struct servent staticsp;
extern char realm[];
#endif /* KRB5_KRB4_COMPAT */

static void cmdscanner (int);
static char *slurpstring (void);


int 
main(argc, argv)
	volatile int argc;
	char **volatile argv;
{
	register char *cp;
	int top;
#ifndef _WIN32
	struct passwd *pw = NULL;
#endif
	char homedir[MAXPATHLEN];
	char *progname = argv[0];

#ifdef _WIN32
	DWORD optionValue = SO_SYNCHRONOUS_NONALERT;
	if (setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&optionValue, sizeof(optionValue)) == SOCKET_ERROR) {
		fprintf(stderr, "ftp: cannot enable synchronous sockets\n");
		exit(1);
	}
#endif

	sp = getservbyname("ftp", "tcp");
	if (sp == 0) {
		fprintf(stderr, "ftp: ftp/tcp: unknown service\n");
		exit(1);
	}
#ifdef KRB5_KRB4_COMPAT
/* GDM need to static sp so that the information is not lost
   when kerberos calls getservbyname */
	memcpy(&staticsp,sp,sizeof(struct servent));
	sp = &staticsp;
#endif /* KRB5_KRB4_COMPAT */
	doglob = 1;
	interactive = 1;
	autoauth = 1;
	autologin = 1;
	forward = 0;
	autoencrypt = 0;
	argc--, argv++;
	while (argc > 0 && **argv == '-') {
		for (cp = *argv + 1; *cp; cp++)
			switch (*cp) {

			case 'd':
				options |= SO_DEBUG;
				debug++;
				break;

#ifdef KRB5_KRB4_COMPAT
			case 'k':
				if (*++cp != '\0')
					strncpy(realm, ++cp, REALM_SZ);
				else if (argc > 1) {
					argc--, argv++;
					strncpy(realm, *argv, REALM_SZ);
				}
				else
					fprintf(stderr, "ftp: -k expects arguments\n");
				goto nextopt;
#endif

			case 'v':
				verbose++;
				break;

			case 't':
				trace++;
				break;

			case 'i':
				interactive = 0;
				break;

			case 'n':
				autologin = 0;
				break;

			case 'g':
				doglob = 0;
				break;

			case 'u':
				autoauth = 0;
				break;

			case 'f':
				forward = 1;
				break;

			case 'x':
				autoencrypt = 1;
				break;

			default:
			  fprintf(stderr,
				  "ftp: %c: unknown option\n", *cp);
			  fprintf(stderr, "Usage: %s [-v] [-d] [-i] [-n] [-g] "
				  "[-k realm] [-f] [-x] [-u] [-t] [host]\n",
				  progname);
			  exit(1);
			}
	nextopt:
		argc--, argv++;
	}
	fromatty = isatty(fileno(stdin));
	if (fromatty)
		verbose++;
	cpend = 0;	/* no pending replies */
	proxy = 0;	/* proxy not active */
#ifndef NO_PASSIVE_MODE
	passivemode = 0; /* passive mode not active */
#endif
	crflag = 1;	/* strip c.r. on ascii gets */
	sendport = -1;	/* not using ports */
	/*
	 * Set up the home directory in case we're globbing.
	 */
#ifdef _WIN32
	cp = getenv("HOME");
	if (cp != NULL) {
		home = homedir;
		(void) strncpy(home, cp, sizeof(homedir) - 1);
		homedir[sizeof(homedir) - 1] = '\0';
	}
#else /* !_WIN32 */
	cp = getlogin();
	if (cp != NULL) {
		pw = getpwnam(cp);
	}
	if (pw == NULL)
		pw = getpwuid(getuid());
	if (pw != NULL) {
		home = homedir;
		(void) strncpy(home, pw->pw_dir, sizeof(homedir) - 1);
		homedir[sizeof(homedir) - 1] = '\0';
	}
#endif /* !_WIN32 */
	if (argc > 0) {
		if (setjmp(toplevel))
			exit(0);
		(void) signal(SIGINT, intr);
#ifdef SIGPIPE
		(void) signal(SIGPIPE, lostpeer);
#endif
		setpeer(argc + 1, argv - 1);
	}
	top = setjmp(toplevel) == 0;
	if (top) {
		(void) signal(SIGINT, intr);
#ifdef SIGPIPE
		(void) signal(SIGPIPE, lostpeer);
#endif
	}
	for (;;) {
		cmdscanner(top);
		top = 1;
	}
}

sigtype
intr(sig)
	int sig;
{

	longjmp(toplevel, 1);
}

sigtype
lostpeer(sig)
	int sig;
{
	extern FILE *cout;
	extern SOCKET data;
	extern char *auth_type;
	extern int clevel;
	extern int dlevel;

	if (connected) {
		if (cout != NULL) {
			(void) shutdown(SOCKETNO(fileno(cout)), 1+1);
			(void) FCLOSE_SOCKET(cout);
			cout = NULL;
		}
		if (data != INVALID_SOCKET) {
			(void) shutdown(data, 1+1);
			(void) closesocket(data);
			data = INVALID_SOCKET;
		}
		connected = 0;
		auth_type = NULL;
		clevel = dlevel = PROT_C;
	}
	pswitch(1);
	if (connected) {
		if (cout != NULL) {
			(void) shutdown(SOCKETNO(fileno(cout)), 1+1);
			(void) FCLOSE_SOCKET(cout);
			cout = NULL;
		}
		connected = 0;
		auth_type = NULL;
		clevel = dlevel = PROT_C;
	}
	proxflag = 0;
	pswitch(0);
}

/*char *
tail(filename)
	char *filename;
{
	register char *s;
	
	while (*filename) {
		s = strrchr(filename, '/');
		if (s == NULL)
			break;
		if (s[1])
			return (s + 1);
		*s = '\0';
	}
	return (filename);
}
*/
/*
 * Command parser.
 */
static void
cmdscanner(top)
	int top;
{
	register struct cmd *c;
	register int l;

	if (!top)
		(void) putchar('\n');
	for (;;) {
		if (fromatty) {
			printf("ftp> ");
			(void) fflush(stdout);
		}
		if (fgets(line, sizeof line, stdin) == NULL)
			quit();
		l = strlen(line);
		if (l == 0)
			break;
		if (line[--l] == '\n') {
			if (l == 0)
				break;
			line[l] = '\0';
		} else if (l == sizeof(line) - 2) {
			printf("sorry, input line too long\n");
			while ((l = getchar()) != '\n' && l != EOF)
				/* void */;
			break;
		} /* else it was a line without a newline */
		makeargv();
		if (margc == 0) {
			continue;
		}
		c = getcmd(margv[0]);
		if (c == (struct cmd *)-1) {
			printf("?Ambiguous command\n");
			continue;
		}
		if (c == 0) {
			printf("?Invalid command\n");
			continue;
		}
		if (c->c_conn && !connected) {
			printf("Not connected.\n");
			continue;
		}
		(*c->c_handler)(margc, margv);
		if (bell && c->c_bell)
			(void) putchar('\007');
		if (c->c_handler != help)
			break;
	}
	(void) signal(SIGINT, intr);
#ifdef SIGPIPE
	(void) signal(SIGPIPE, lostpeer);
#endif
}

struct cmd *
getcmd(name)
	register char *name;
{
	extern struct cmd cmdtab[];
	register char *p, *q;
	register struct cmd *c, *found;
	register int nmatches, longest;

	longest = 0;
	nmatches = 0;
	found = 0;
	for (c = cmdtab; (p = c->c_name) != NULL; c++) {
		for (q = name; *q == *p++; q++)
			if (*q == 0)		/* exact match? */
				return (c);
		if (!*q) {			/* the name was a prefix */
			if (q - name > longest) {
				longest = q - name;
				nmatches = 1;
				found = c;
			} else if (q - name == longest)
				nmatches++;
		}
	}
	if (nmatches > 1)
		return ((struct cmd *)-1);
	return (found);
}

/*
 * Slice a string up into argc/argv.
 */

int slrflag;

void makeargv()
{
	char **argp;

	margc = 0;
	argp = margv;
	stringbase = line;		/* scan from first of buffer */
	argbase = argbuf;		/* store from first of buffer */
	slrflag = 0;
	while ((*argp++ = slurpstring())) {
		margc++;
		if (margc == sizeof(margv)/sizeof(margv[0])) {
			printf("sorry, too many arguments in input line\n");
			margc = 0;
			margv[0] = 0;
			return;
		}
	}
}

/*
 * Parse string into argbuf;
 * implemented with FSM to
 * handle quoting and strings
 */
static char *
slurpstring()
{
	int got_one = 0;
	register char *sb = stringbase;
	register char *ap = argbase;
	char *tmp = argbase;		/* will return this if token found */

	if (*sb == '!' || *sb == '$') {	/* recognize ! as a token for shell */
		switch (slrflag) {	/* and $ as token for macro invoke */
			case 0:
				slrflag++;
				stringbase++;
				return ((*sb == '!') ? "!" : "$");
				/* NOTREACHED */
			case 1:
				slrflag++;
				altarg = stringbase;
				break;
			default:
				break;
		}
	}

S0:
	switch (*sb) {

	case '\0':
		goto EXIT;

	case ' ':
	case '\t':
		sb++; goto S0;

	default:
		switch (slrflag) {
			case 0:
				slrflag++;
				break;
			case 1:
				slrflag++;
				altarg = sb;
				break;
			default:
				break;
		}
		goto S1;
	}

S1:
	switch (*sb) {

	case ' ':
	case '\t':
	case '\0':
		goto EXIT;	/* end of token */

	case '\\':
		sb++; goto S2;	/* slurp next character */

	case '"':
		sb++; goto S3;	/* slurp quoted string */

	default:
		*ap++ = *sb++;	/* add character to token */
		got_one = 1;
		goto S1;
	}

S2:
	switch (*sb) {

	case '\0':
		goto EXIT;

	default:
		*ap++ = *sb++;
		got_one = 1;
		goto S1;
	}

S3:
	switch (*sb) {

	case '\0':
		goto EXIT;

	case '"':
		sb++; goto S1;

	default:
		*ap++ = *sb++;
		got_one = 1;
		goto S3;
	}

EXIT:
	if (got_one)
		*ap++ = '\0';
	argbase = ap;			/* update storage pointer */
	stringbase = sb;		/* update scan pointer */
	if (got_one) {
		return(tmp);
	}
	switch (slrflag) {
		case 0:
			slrflag++;
			break;
		case 1:
			slrflag++;
			altarg = (char *) 0;
			break;
		default:
			break;
	}
	return((char *)0);
}

#define	HELPINDENT ((int) sizeof("disconnect"))

/*
 * Help command.
 * Call each command handler with argc == 0 and argv[0] == name.
 */
void help(argc, argv)
	int argc;
	char *argv[];
{
	extern struct cmd cmdtab[];
	register struct cmd *c;

	if (argc == 1) {
		register int i, j, w, k;
		int columns, width = 0, lines;
		extern int NCMDS;

		printf("Commands may be abbreviated.  Commands are:\n\n");
		for (c = cmdtab; c < &cmdtab[NCMDS]; c++) {
			int len = strlen(c->c_name);

			if (len > width)
				width = len;
		}
		width = (width + 8) &~ 7;
		columns = 80 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			for (j = 0; j < columns; j++) {
				c = cmdtab + j * lines + i;
				if (c->c_name && (!proxy || c->c_proxy)) {
					printf("%s", c->c_name);
				}
				else if (c->c_name) {
					for (k=0; k < strlen(c->c_name); k++) {
						(void) putchar(' ');
					}
				}
				if (c + lines >= &cmdtab[NCMDS]) {
					printf("\n");
					break;
				}
				w = strlen(c->c_name);
				while (w < width) {
					w = (w + 8) &~ 7;
					(void) putchar('\t');
				}
			}
		}
		return;
	}
	while (--argc > 0) {
		register char *arg;
		arg = *++argv;
		c = getcmd(arg);
		if (c == (struct cmd *)-1)
			printf("?Ambiguous help command %s\n", arg);
		else if (c == (struct cmd *)0)
			printf("?Invalid help command %s\n", arg);
		else
			printf("%-*s\t%s\n", HELPINDENT,
				c->c_name, c->c_help);
	}
}
