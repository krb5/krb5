/*
 * Copyright (c) 1985 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static	char sccsid[] = "@(#)getpass.c 1.1 90/04/28 SMI"; /* from UCB 5.4 3/7/86 */
#endif /* not lint */

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#include <stdio.h>

static DWORD old_mode;
static HANDLE cons_handle;

BOOL WINAPI
GetPassConsoleControlHandler(DWORD dwCtrlType)
{
	switch(dwCtrlType){
	case CTRL_BREAK_EVENT:
	case CTRL_C_EVENT:
		printf("Interrupt\n");
		fflush(stdout);
		(void) SetConsoleMode(cons_handle, old_mode);
		ExitProcess(-1);
		break;
	default:
		break;
	}
	return TRUE;
}

char *
mygetpass(char *prompt)
{
	DWORD new_mode;
	char *ptr;
	int scratchchar;
	static char password[50+1];
	int pwsize = sizeof(password);

	cons_handle = GetStdHandle(STD_INPUT_HANDLE);
	if (cons_handle == INVALID_HANDLE_VALUE)
		return NULL;
	if (!GetConsoleMode(cons_handle, &old_mode))
		return NULL;

	new_mode = old_mode;
	new_mode |=  ( ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT );
	new_mode &= ~( ENABLE_ECHO_INPUT );

	if (!SetConsoleMode(cons_handle, new_mode))
		return NULL;

	SetConsoleCtrlHandler(&GetPassConsoleControlHandler, TRUE);

	(void) fputs(prompt, stdout);
	(void) fflush(stdout);
	(void) memset(password, 0, pwsize);

	if (fgets(password, pwsize, stdin) == NULL) {
		if (ferror(stdin))
			goto out;
		(void) putchar('\n');
	}
	else {
		(void) putchar('\n');

		if ((ptr = strchr(password, '\n')))
			*ptr = '\0';
		else /* need to flush */
			do {
				scratchchar = getchar();
			} while (scratchchar != EOF && scratchchar != '\n');
	}

out:
	(void) SetConsoleMode(cons_handle, old_mode);
	SetConsoleCtrlHandler(&GetPassConsoleControlHandler, FALSE);

	return password;
}

#else /* !_WIN32 */

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
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

#include "ftp_var.h"

static	FILE *fi;

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
	register int c;
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

#endif /* !_WIN32 */
