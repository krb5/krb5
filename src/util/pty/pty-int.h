/* Includes needed by libpty*/
#ifndef __PTY_INT_H__
#include <pty_err.h>
#include <sys/types.h>
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#ifdef HAVE_UTMPX_H
#include <utmpx.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef __SCO__
#include <sys/unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <stdio.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/time.h>
#include <ctype.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <pwd.h>
     
#ifdef HAVE_SYS_LABEL_H
/* only SunOS 4? */
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif
     
#include <signal.h>

#ifdef hpux
#include <sys/ptyio.h>
#endif
#ifdef sysvimp
#include <compat.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_STREAMS
#include <sys/stream.h>
#include <sys/stropts.h>
#endif

#if defined(POSIX_TERMIOS) && !defined(ultrix)
#include <termios.h>
#else
#include <sgtty.h>
#endif
     
#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <sys/param.h>


#ifdef HAVE_STREAMS
/* krlogin doesn't test sys/tty... */
#ifdef HAVE_SYS_TTY_H
#include <sys/tty.h>
#endif



#ifdef HAVE_SYS_PTYVAR_H
/* Solaris actually uses packet mode, so the real macros are needed too */
#include <sys/ptyvar.h>
#endif
#endif

#if defined(HAVE_VHANGUP) && !defined(OPEN_CTTY_ONLY_ONCE) 
#define VHANG_first /* Breaks under Ultrix and others where you cannot get controlling terminal twice.*/
#define VHANG_LAST
#endif

/* Internal functions */
#ifdef __STDC__
void initialize_pty_error_table(void);
long ptyint_void_association(void);
long ptyint_open_ctty (char *slave, int *fd);
long ptyint_update_wtmp (struct utmp *ut, char *host);

void ptyint_vhangup(void);
#else /*__STDC__*/

long ptyint_void_association();
void ptyint_vhangup();
void initialize_pty_error_table();
long ptyint_update_wtmp();
#endif /* __STDC__*/

#define __PTY_INT_H__
#endif
