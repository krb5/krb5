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
 * A rant on the nature of pseudo-terminals:
 * -----------------------------------------
 *
 * Controlling terminals and job control:
 *
 * First, some explanation of job control and controlling terminals is
 * necessary for background.  This discussion applies to hardwired
 * terminals as well as ptys.  On most modern systems, all processes
 * belong to a process group.  A process whose process group id (pgid)
 * is the sames as its pid is the process group leader of its process
 * group.  Process groups belong to sessions.  On a modern system, a
 * process that is not currently a process group leader may create a
 * new session by calling setsid(), which makes it a session leader as
 * well as a process group leader, and also removes any existing
 * controlling terminal (ctty) association.  Only a session leader may
 * acquire a ctty.  It's not clear how systems that don't have
 * setsid() handle ctty acquisition, though probably any process group
 * leader that doesn't have a ctty may acquire one that way.
 *
 * A terminal that is a ctty has an associated foreground process
 * group, which is a member of the terminal's associated session.
 * This process group gets read/write access to the terminal and will
 * receive terminal-generated signals (e.g. SIGINT, SIGTSTP).  Process
 * groups belonging to the session but not in the foreground may get
 * signals that suspend them if they try to read/write from the ctty,
 * depending on various terminal settings.
 *
 * On many systems, the controlling process (the session leader
 * associated with a ctty) exiting will cause the session to lose its
 * ctty, even though some processes may continue to have open file
 * descriptors on the former ctty.  It is possible for a process to
 * have no file descriptors open on its controlling tty, but to
 * reacquire such by opening /dev/tty, as long as its session still
 * has a ctty.
 *
 * On ptys in general:
 *
 * Ptys have a slave side and a master side.  The slave side looks
 * like a hardwired serial line to the application that opens it;
 * usually, telnetd or rlogind, etc. opens the slave and hands it to
 * the login program as stdin/stdout/stderr.  The master side usually
 * gets the actual network traffic written to/from it.  Roughly, the
 * master and slave are two ends of a bidirectional pair of FIFOs,
 * though this can get complicated by other things.
 *
 * The master side of a pty is theoretically a single-open device.
 * This MUST be true on systems that have BSD-style ptys, since there
 * is usually no way to allocate an unused pty except by attempting to
 * open all the master pty nodes in the system.
 *
 * Often, but not always, the last close of a slave device will cause
 * the master to get an EOF.  Closing the master device will sometimes
 * cause the foreground process group of the slave to get a SIGHUP,
 * but that may depend on terminal settings.
 *
 * BSD ptys:
 *
 * On a BSD-derived system, the master nodes are named like
 * /dev/ptyp0, and the slave nodes are named like /dev/ttyp0.  The
 * last two characters are the variable ones, and a shell-glob type
 * pattern for a slave device is usually of the form
 * /dev/tty[p-z][0-9a-f], though variants are known to exist.
 *
 * System V cloning ptys:
 *
 * There is a cloning master device (usually /dev/ptmx, but the name
 * can vary) that gets opened.  Each open of the cloning master
 * results in an open file descriptor of a unique master device.  The
 * application calls ptsname() to find the pathname to the slave node.
 *
 * In theory, the slave side of the pty is locked out until the
 * process opening the master calls grantpt() to adjust permissions
 * and unlockpt() to unlock the slave.  It turns out that Unix98
 * doesn't require that the slave actually get locked out, or that
 * unlockpt() actually do anything on such systems.  At least AIX
 * allows the slave to be opened prior to calling unlockpt(), but most
 * other SysV-ish systems seem to actually lock out the slave.
 *
 * Pty security:
 *
 * It's not guaranteed on a BSD-ish system that a slave can't be
 * opened when the master isn't open.  It's even possible to acquire
 * the slave as a ctty (!) if the open is done as non-blocking.  It's
 * possible to open the master corresponding to an open slave, which
 * creates some security issues: once this master is open, data
 * written to the slave will actually pass to the master.
 *
 * On a SysV-ish system, the close of the master will invalidate any
 * open file descriptors on the slave.
 *
 * In general, there are two functions that can be used to "clean" a
 * pty slave, revoke() and vhangup().  revoke() will invalidate all
 * file descriptors open on a particular pathname (often this only
 * works on terminal devices), usually by invalidating the underlying
 * vnode.  vhangup() will send a SIGHUP to the foreground process
 * group of the control terminal.  On many systems, it also has
 * revoke() semantics.
 *
 * If a process acquires a controlling terminal in order to perform a
 * vhangup(), the reopen of the controlling terminal after the
 * vhangup() call should be done prior to the close of the file
 * descriptor used to initially acquire the controlling terminal,
 * since that will likely prevent the process on the master side from
 * reading a spurious EOF due to all file descriptors to the slave
 * being closed.
 *
 * Known quirks of various OSes:
 *
 * AIX 4.3.3:
 *
 * If the environment variable XPG_SUS_ENV is not equal to "ON", then
 * it's possible to open the slave prior to calling unlockpt().
 */

/*
 * NOTE: this program will get reworked at some point to actually test
 * passing of data between master and slave, and to do general cleanup.
 *
 * This is rather complex, so it bears some explanation.
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
 *
 * If this doesn't fail, child3 will attempt to write to the open
 * slave fd.  This should fail unless a prior call to revoke(),
 * etc. failed due to lack of permissions, e.g. NetBSD when running as
 * non-root.
 */

#include "com_err.h"
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
void testex(int, const char *);
void testwr(int, const char *);
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

#if 0
    printf("rdsync: %s: starting\n", caller);
    fflush(stdout);
#endif
    while ((n = read(fd, &c, 1)) < 0) {
	if (errno != EINTR) {
	    fprintf(stderr, "rdsync: %s", caller);
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

    fd = open("/dev/tty", O_RDWR|O_NONBLOCK);
    if (fd < 0) {
	printf("%s: no ctty\n", caller);
    } else {
	printf("%s: have ctty\n", caller);
    }
}

void
testex(int fd, const char *caller)
{
    fd_set rfds, xfds;
    struct timeval timeout;
    int n;
    char c;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_ZERO(&xfds);
    FD_SET(fd, &rfds);
    FD_SET(fd, &xfds);

    n = select(fd + 1, &rfds, NULL, &xfds, &timeout);
    if (n < 0) {
	fprintf(stderr, "testex: %s: ", caller);
	perror("select");
    }
    if (n) {
	if (FD_ISSET(fd, &rfds) || FD_ISSET(fd, &xfds)) {
	    n = read(fd, &c, 1);
	    if (!n) {
		printf("testex: %s: got EOF\n", caller);
		fflush(stdout);
		return;
	    } else if (n == -1) {
		printf("testex: %s: got errno=%ld (%s)\n",
		       caller, (long)errno, strerror(errno));
	    } else {
		printf("testex: %s: read 1 byte!?\n", caller);
	    }
	}
    } else {
	printf("testex: %s: no exceptions or readable fds\n", caller);
    }
}

void
testwr(int fd, const char *caller)
{
    fd_set wfds;
    struct timeval timeout;
    int n;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    n = select(fd + 1, NULL, &wfds, NULL, &timeout);
    if (n < 0) {
	fprintf(stderr, "testwr: %s: ", caller);
	perror("select");
    }
    if (n) {
	if (FD_ISSET(fd, &wfds)) {
	    printf("testwr: %s: is writable\n", caller);
	    fflush(stdout);
	}
    }
}


void
child3(void)
{
    int n;

    ptyint_void_association();
    slavefd = open(slave, O_RDWR|O_NONBLOCK);
    if (slavefd < 0) {
	wrsync(p1p[1], 1, "[02] child3->parent");
	printf("child3: failed reopen of slave\n");
	fflush(stdout);
	exit(1);
    }
#ifdef TIOCSCTTY
    ioctl(slavefd, TIOCSCTTY, 0);
#endif

    printf("child3: reopened slave\n");
    testctty("child3: after reopen of slave");
    testwr(slavefd, "child3: after reopen of slave");
    testex(slavefd, "child3: after reopen of slave");
    close(slavefd);
    testctty("child3: after close of slave");

    /*
     * Sync for parent to close master.
     */
    wrsync(p1p[1], 0, "[02] child3->parent");
    rdsync(pp1[0], NULL, "[03] parent->child3");

    testctty("child3: after close of master");
    printf("child3: attempting reopen of slave\n");
    fflush(stdout);
    slavefd = open(slave, O_RDWR|O_NONBLOCK);
    if (slavefd < 0) {
	printf("child3: failed reopen of slave after master close: "
	       "errno=%ld (%s)\n", (long)errno, strerror(errno));
	wrsync(p1p[1], 0, "[04] child3->parent");
	fflush(stdout);
	exit(0);
    }
    if (fcntl(slavefd, F_SETFL, 0) == -1) {
	perror("child3: fcntl");
	wrsync(p1p[1], 2, "[04] child3->parent");
	exit(1);
    }
#ifdef TIOCSCTTY
    ioctl(slavefd, TIOCSCTTY, 0);
#endif
    printf("child3: reopened slave after master close\n");
    testctty("child3: after reopen of slave after master close");
    testwr(slavefd, "child3: after reopen of slave after master close");
    testex(slavefd, "child3: after reopen of slave after master close");
    n = write(slavefd, "foo", 4);
    if (n < 0) {
	printf("child3: writing to slave of closed master: errno=%ld (%s)\n",
	       (long)errno, strerror(errno));
	wrsync(p1p[1], 1, "[04] child3->parent");
    } else {
	printf("child3: wrote %d byes to slave of closed master\n", n);
	fflush(stdout);
	wrsync(p1p[1], 2, "[04] child3->parent");
    }
    rdsync(pp1[0], NULL, "[05] parent->child3");
    testex(slavefd, "child3: after parent reopen of master");
    testwr(slavefd, "child3: after parent reopen of master");
    fflush(stdout);
    n = write(slavefd, "bar", 4);
    if (n < 0) {
	perror("child3: writing to slave");
    } else {
	printf("child3: wrote %d bytes to slave\n", n);
	fflush(stdout);
    }
    wrsync(p1p[1], 0, "[06] child3->parent");
    rdsync(pp1[0], NULL, "[07] parent->child3");
    wrsync(p1p[1], 0, "[08] child3->parent");
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
	wrsync(p21[1], 1, "[00] child2->child1");
	perror("child2: sigaction");
	fflush(stdout);
	exit(1);
    }
    printf("child2: set up signal handler\n");
    testctty("child2: after start");
    testwr(slavefd, "child2: after start");
    wrsync(p21[1], 0, "[00] child2->child1");
    rdsync(pp1[0], NULL, "[01] parent->child2");

    testctty("child2: after child1 exit");
    testex(slavefd, "child2: after child1 exit");
    testwr(slavefd, "child2: after child1 exit");
    close(slavefd);
    testctty("child2: after close of slavefd");
    slavefd = open(slave, O_RDWR|O_NONBLOCK);
    if (slavefd < 0) {
	wrsync(p1p[1], 1, "[02] child2->parent");
	printf("child2: failed reopen of slave\n");
	fflush(stdout);
	exit(1);
    }
#ifdef TIOCSCTTY
    ioctl(slavefd, TIOCSCTTY, 0);
#endif
    printf("child2: reopened slave\n");
    testctty("child2: after reopen of slave");
    fflush(stdout);
    close(slavefd);
    pid3 = fork();
    if (!pid3) {
	child3();
    } else if (pid3 == -1) {
	wrsync(p1p[1], 1, "[02] child2->parent");
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
    int status;

#if 0
    setuid(1);
#endif
    close(pp1[1]);
    close(p1p[0]);
    close(masterfd);
    ptyint_void_association();
    slavefd = open(slave, O_RDWR|O_NONBLOCK);
    if (slavefd < 0) {
	perror("child1: open slave");
	exit(1);
    }
#ifdef TIOCSCTTY
    ioctl(slavefd, TIOCSCTTY, 0);
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
    rdsync(p21[0], &status, "[00] child2->child1");
    exit(status);
}

int
main(int argc, char *argv[])
{
    long retval;
    int status;
    char buf[4];
    int n;

    prog = argv[0];

    printf("parent: pid=%ld\n", (long)getpid());

    retval = ptyint_getpty_ext(&masterfd, slave, sizeof(slave), 0);

    if (retval) {
	com_err(prog, retval, "open master");
	exit(1);
    }
#if 0
    chown(slave, 1, -1);
#endif
    printf("parent: master opened; slave=%s\n", slave);
    fflush(stdout);

#if defined(HAVE_GRANTPT) && defined(HAVE_STREAMS)
#ifdef O_NOCTTY
    printf("parent: attempting to open slave before unlockpt\n");
    fflush(stdout);
    slavefd = open(slave, O_RDWR|O_NONBLOCK|O_NOCTTY);
    if (slavefd < 0) {
	printf("parent: failed slave open before unlockpt errno=%ld (%s)\n",
	       (long)errno, strerror(errno));
    } else {
	printf("parent: WARNING: "
	       "succeeded in opening slave before unlockpt\n");
    }
    close(slavefd);
#endif
    if (grantpt(masterfd) < 0) {
	perror("parent: grantpt");
	exit(1);
    }
    if (unlockpt(masterfd) < 0) {
	perror("parent: unlockpt");
	exit(1);
    }
#endif /* HAVE_GRANTPT && HAVE_STREAMS */

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
    if (status1)
	exit(status1);

    wrsync(pp1[1], 0, "[01] parent->child2");
    rdsync(p1p[0], &status, "[02] child3->parent");
    if (status) {
	fprintf(stderr, "child2 or child3 got an error\n");
	exit(1);
    }

    printf("parent: closing master\n");
    fflush(stdout);
    close(masterfd);
    chmod(slave, 0666);
    printf("parent: closed master\n");
    wrsync(pp1[1], 0, "[03] parent->child3");

    rdsync(p1p[0], &status, "[04] child3->parent");
    switch (status) {
    case 1:
	break;
    case 0:
	exit(0);
    default:
	fprintf(stderr, "child3 got an error\n");
	fflush(stdout);
	exit(1);
    }

    retval = pty_getpty(&masterfd, slave2, sizeof(slave2));
    printf("parent: new master opened; slave=%s\n", slave2);
#if 0
#ifdef HAVE_REVOKE
    printf("parent: revoking\n");
    revoke(slave2);
#endif
#endif
    fflush(stdout);
    wrsync(pp1[1], 0, "[05] parent->child3");
    rdsync(p1p[0], NULL, "[06] child3->parent");

    n = read(masterfd, buf, 4);
    if (n < 0) {
	perror("parent: reading from master");
    } else {
	printf("parent: read %d bytes (%.*s) from master\n", n, n, buf);
	fflush(stdout);
    }
    chmod(slave2, 0666);
    close(masterfd);
    wrsync(pp1[1], 0, "[07] parent->child3");
    rdsync(p1p[0], NULL, "[08] child3->parent");
    fflush(stdout);
    exit(0);
}
