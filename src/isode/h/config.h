/* this should be enough for everything... */

#define	VSPRINTF		/* has vprintf(3s) routines */
#define	TCP			/* has TCP/IP (of course) */
#define	SOCKETS			/*   provided by sockets */
#define	GETDENTS		/* has <dirent.h> */

#ifdef __svr4__
/* SYS5 is for termio instead of sgttyb */
#define SYS5
/* SVR4 turns off strdup */
#define SVR4
#endif

#ifdef mips
/* not sys5 */
#define BSD42
#endif

#ifdef _AIX
/* SYS5 is also for fcntl.h instead of sys/fcntl.h */
#define SYS5
/* AIX lets manifest.h fix up SYS5NLY */
#define AIX
#endif

#ifdef __linux__
/* SYS5 is for termio instead of sgttyb */
#define SYS5
#endif

#ifdef sun
#ifndef __svr4__
#define SUNOS4
#endif
#endif

/* add more for the various recent BSD variants */
#if defined(__bsdi__) || defined(__NetBSD__) || defined(__FreeBSD__)
#define BSD44
#define BSD42
#endif

#ifdef vax
#ifdef unix
#define BSD42
#endif
#endif
