/*
 * Copyright 2001 by the Massachusetts Institute of Technology.
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * M.I.T. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

/*
 * This bears some explanation.
 *
 * There are multiple child processes and a parent process.  These
 * communicate via pipes (which we assume here to be unidirectional).
 * The pipes are:
 *
 * pp1 - parent -> any children
 *
 * p1p - any children -> parent
 *
 * p21 - only child2 -> child1
 *
 * A parent process will acquire a pty master and slave via
 * pty_getpty().  It will then fork a process, child1.  It then does a
 * waitpid() for child1, and then writes to child2 via syncpipe pp1.
 * It then reads from child3 via syncpipe p1p, then closes the
 * master.  It writes to child3 via syncpipe pp1 to indicate that it
 * has closed the master.  It then reads from child3 via syncpipe p1p
 * and exits with a value appropriate to what it read from child3.
 *
 * child1 will acquire the slave as its ctty and fork child2; child1
 * will exit once it reads from the syncpipe p21 from child2.
 *
 * child2 will set a signal handler for SIGHUP and then write to
 * child1 via syncpipe p21 to indicate that child2 has set up the
 * handler.  It will then read from the syncpipe pp1 from the parent
 * to confirm that the parent has seen child1 exit, and then checks to
 * see if it still has a ctty.  Under Unix98, and likely earlier
 * System V derivatives, the exiting of the session leader associated
 * with a ctty (in this case, child1) will cause the entire session to
 * lose its ctty.
 *
 * child2 will then check to see if it can reopen the slave, and
 * whether it has a ctty after reopening it.  This should fail on most
 * systems.
 *
 * child2 will then fork child3 and immediately exit.
 *
 * child3 will write to the syncpipe p1p and read from the syncpipe
 * pp1.  It will then check if it has a ctty and then attempt to
 * reopen the slave.  This should fail.  It will then write to the
 * parent via syncpipe p1p and exit.
 */

#include <com_err.h>
#include "libpty.h"
#include "pty-int.h"
#include <sys/wait.h>
#include <stdlib.h>

char *prog;
int masterfd, slavefd;
char slave[64], slave2[64];
pid_t pid1, pid2, pid3;
int status1, status2;
int pp1[2], p1p[2], p21[2];

void handler(int);
void rdsync(int, int *, const char *);
void wrsync(int, int, const char *);
void testctty(const char *);
void child1(void);
void child2(void);
void child3(void);

void
handler(int sig)
{
    printf("pid %ld got signal %d\n", (long)getpid(), sig);
    fflush(stdout);
    return;
}

void
rdsync(int fd, int *status, const char *caller)
{
    int n;
    char c;

    while ((n = read(fd, &c, 1)) < 0) {
	if (errno != EINTR) {
	    fprintf(stderr, "wrsync: %s", caller);
	    perror("");
	    exit(1);
	} else {
	    printf("rdsync: %s: got EINTR; looping\n", caller);
	    fflush(stdout);
	}
    }
    if (!n) {
	fprintf(stderr, "rdsync: %s: unexpected EOF\n", caller);
	exit(1);
    }
    printf("rdsync: %s: got sync byte\n", caller);
    fflush(stdout);
    if (status != NULL)
	*status = c;
}

void
wrsync(int fd, int status, const char *caller)
{
    int n;
    char c;

    c = status;
    while ((n = write(fd, &c, 1)) < 0) {
	if (errno != EINTR) {
	    fprintf(stderr, "wrsync: %s", caller);
	    perror("");
	    exit(1);
	} else {
	    printf("wrsync: %s: got EINTR; looping\n", caller);
	    fflush(stdout);
	}
    }
#if 0
    printf("wrsync: %s: sent sync byte\n", caller);
#endif
    fflush(stdout);
}

void
testctty(const char *caller)
{
    int fd;

    fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
	printf("%s: no ctty\n", caller);
    } else {
	printf("%s: have ctty\n", caller);
    }
}

void
child3(void)
{

    ptyint_void_association();
    slavefd = open(slave, O_RDWR);
    if (slavefd < 0) {
	printf("child3: failed reopen of slave\n");
	fflush(stdout);
	exit(0);
    }
#ifdef TIOCSTTY
    ioctl(slavefd, TIOCSTTY, 0);
#endif

    printf("child3: reopened slave\n");
    testctty("child3: after reopen of slave");
    close(slavefd);
    testctty("child3: after close of slave");

    /*
     * Sync for parent to close master.
     */
    wrsync(p1p[1], 0, "child3->parent");
    rdsync(pp1[0], NULL, "parent->child3");

    testctty("child3: after close of master");
    slavefd = open(slave, O_RDWR);
    if (slavefd < 0) {
	printf("child3: failed reopen of slave after master close "
	       "errno=%ld (%s)\n", (long)errno, strerror(errno));
	wrsync(p1p[1], 0, "child3->parent");
	fflush(stdout);
	exit(0);
    }
    printf("child3: reopened slave after master close\n");
    testctty("child3: after reopen of slave after master close\n");
    wrsync(p1p[1], 1, "child3->parent");
    fflush(stdout);
    exit(0);
}

void
child2(void)
{
    struct sigaction sa;

    close(p21[0]);
    setpgid(0, 0);
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handler;
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
	perror("child2: sigaction");
	fflush(stdout);
	exit(1);
    }
    printf("child2: set up signal handler\n");
    testctty("child2: after start");
    wrsync(p21[1], 0, "child2->child1");
    rdsync(pp1[0], NULL, "parent->child2");
    testctty("child2: after child1 exit");
    close(slavefd);
    testctty("child2: after close of slavefd");
    slavefd = open(slave, O_RDWR);
    if (slavefd < 0) {
	printf("child2: failed reopen of slave\n");
	fflush(stdout);
	exit(0);
    }
    printf("child2: reopened slave\n");
    testctty("child2: after reopen of slave");
    fflush(stdout);
    close(slavefd);
    pid3 = fork();
    if (!pid3) {
	child3();
    } else if (pid3 == -1) {
	perror("child2: fork of child3");
	exit(1);
    }
    printf("child2: forked child3=%ld\n", (long)pid3);
    fflush(stdout);
    exit(0);

}

void
child1(void)
{

    close(pp1[1]);
    close(p1p[0]);
    close(masterfd);
    ptyint_void_association();
    slavefd = open(slave, O_RDWR);
    if (slavefd < 0) {
	perror("child1: open slave");
	exit(1);
    }
#ifdef TIOCSTTY
    ioctl(slavefd, TIOCSTTY, 0);
#endif

    printf("child1: opened slave\n");
    testctty("child1: after slave open");

    if (pipe(p21) < 0) {
	perror("pipe child2->child1");
	exit(1);
    }
    pid2 = fork();
    if (!pid2) {
	child2();
    } else if (pid2 == -1) {
	perror("child1: fork child2");
	exit(1);
    }
    close(p21[1]);
    printf("child1: forked child2=%ld\n", (long)pid2);
    fflush(stdout);
    rdsync(p21[0], NULL, "child2->child1");
    exit(0);
}

int
main(int argc, char *argv[])
{
    long retval;
    int status;

    prog = argv[0];

    retval = pty_getpty(&masterfd, slave, sizeof(slave));

    if (retval) {
	com_err(prog, retval, "open master");
	exit(1);
    }
    printf("parent: master opened; slave=%s\n", slave);
    fflush(stdout);

    if (pipe(pp1) < 0) {
	perror("pipe parent->child1");
	exit(1);
    }
    if (pipe(p1p) < 0) {
	perror("pipe child1->parent");
	exit(1);
    }

    pid1 = fork();
    if (!pid1) {
	child1();
    } else if (pid1 == -1) {
	perror("fork of child1");
	exit(1);
    }
    printf("parent: forked child1=%ld\n", (long)pid1);
    fflush(stdout);
    if (waitpid(pid1, &status1, 0) < 0) {
	perror("waitpid for child1");
	exit(1);
    }
    printf("parent: child1 exited, status=%d\n", status1);
    wrsync(pp1[1], 0, "parent->child2");
    rdsync(p1p[0], NULL, "child3->parent");
    printf("parent: closing master\n");
    fflush(stdout);
    close(masterfd);
    printf("parent: closed master\n");
    wrsync(pp1[1], 0, "parent->child3");
    rdsync(p1p[0], &status, "child3->parent");
    if (status) {
	fprintf(stderr, "got status %d\n", status);
    }
    exit(status);
}
