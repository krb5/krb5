/*
 * Copyright (c) 1985 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static	char sccsid[] = "@(#)getpass.c 1.1 90/04/28 SMI"; /* from UCB 5.4 3/7/86 */
#endif /* not lint */

#include <stdio.h>
#include <signal.h>

#if defined (POSIX) || defined (POSIX_TERMIOS)
#include <termios.h>
static	struct termios ttyo, ttyb;
#define stty(f, t) tcsetattr(f, TCSANOW, t)
#define gtty(f, t) tcgetattr(f, t)
#else
#include <sgtty.h>
static	struct sgttyb ttyo, ttyb;
#endif

static	FILE *fi;

#define sig_t my_sig_t
#define sigtype krb5_sigtype
typedef sigtype (*sig_t)();

static sigtype
intfix(sig)
	int sig;
{
	if (fi != NULL)
		(void) stty(fileno(fi), &ttyo);
	exit(SIGINT);
}

char *
mygetpass(prompt)
char *prompt;
{
	register char *p;
	register c;
	static char pbuf[50+1];
	sigtype (*sig)();

	if ((fi = fopen("/dev/tty", "r")) == NULL)
		fi = stdin;
	else
		setbuf(fi, (char *)NULL);
	sig = signal(SIGINT, intfix);
	(void) gtty(fileno(fi), &ttyb);
	ttyo = ttyb;
#if defined (POSIX) || defined (POSIX_TERMIOS)
	ttyb.c_lflag &= ~ECHO;
#else
	ttyb.sg_flags &= ~ECHO;
#endif
	(void) stty(fileno(fi), &ttyb);
	fprintf(stderr, "%s", prompt); (void) fflush(stderr);
	for (p=pbuf; (c = getc(fi))!='\n' && c!=EOF;) {
		if (p < &pbuf[sizeof(pbuf)-1])
			*p++ = c;
	}
	*p = '\0';
	fprintf(stderr, "\n"); (void) fflush(stderr);
	(void) stty(fileno(fi), &ttyo);
	(void) signal(SIGINT, sig);
	if (fi != stdin)
		(void) fclose(fi);
	return(pbuf);
}
