/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static	char sccsid[] = "@(#)pclose.c 1.1 90/04/28 SMI"; /* from UCB 1.2 3/7/86 */
#endif /* not lint */

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <signal.h>
#include <sys/param.h>
#include <sys/wait.h>
#define sig_t my_sig_t
#define sigtype krb5_sigtype
typedef sigtype (*sig_t)();

#define	tst(a,b)	(*mode == 'r'? (b) : (a))
#define	RDR	0
#define	WTR	1

static	int *popen_pid;
static	int nfiles;

#ifndef HAVE_GETDTABLESIZE
#include <sys/resource.h>
int getdtablesize() {
  struct rlimit rl;
  getrlimit(RLIMIT_NOFILE, &rl);
  return rl.rlim_cur;
}
#endif

FILE *
mypopen(cmd,mode)
	char *cmd;
	char *mode;
{
	int p[2];
	volatile int myside, hisside;
	int pid;

	if (nfiles <= 0)
		nfiles = getdtablesize();
	if (popen_pid == NULL) {
		popen_pid = (int *)malloc((unsigned) nfiles * sizeof *popen_pid);
		if (popen_pid == NULL)
			return (NULL);
		for (pid = 0; pid < nfiles; pid++)
			popen_pid[pid] = -1;
	}
	if (pipe(p) < 0)
		return (NULL);
	myside = tst(p[WTR], p[RDR]);
	hisside = tst(p[RDR], p[WTR]);
	if ((pid = fork()) == 0) {
		/* myside and hisside reverse roles in child */
		(void) close(myside);
		if (hisside != tst(0, 1)) {
			(void) dup2(hisside, tst(0, 1));
			(void) close(hisside);
		}
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}
	if (pid == -1) {
		(void) close(myside);
		(void) close(hisside);
		return (NULL);
	}
	popen_pid[myside] = pid;
	(void) close(hisside);
	return (fdopen(myside, mode));
}

sigtype
pabort(sig)
	int sig;
{
	extern int mflag;

	mflag = 0;
}

mypclose(ptr)
	FILE *ptr;
{
	int child, pid;
#ifdef USE_SIGPROCMASK
	sigset_t old, new;
#else
	int omask;
#endif
	sigtype pabort(), (*istat)();
#ifdef WAIT_USES_INT
	int status;
#else
	union wait status;
#endif

	child = popen_pid[fileno(ptr)];
	popen_pid[fileno(ptr)] = -1;
	(void) fclose(ptr);
	if (child == -1)
		return (-1);
	istat = signal(SIGINT, pabort);
#ifdef USE_SIGPROCMASK
	sigemptyset(&old);
	sigemptyset(&new);
	sigaddset(&new,SIGQUIT);
	sigaddset(&new,SIGHUP);
	sigprocmask(SIG_BLOCK, &new, &old);
	while ((pid = wait(&status)) != child && pid != -1)
		;
	sigprocmask(SIG_SETMASK, &old, NULL);
#else
	omask = sigblock(sigmask(SIGQUIT)|sigmask(SIGHUP));
	while ((pid = wait(&status)) != child && pid != -1)
		;
	sigsetmask(omask);
#endif
	(void) signal(SIGINT, istat);
	return (pid == -1 ? -1 : 0);
}
