/*
 * Header file for manipulation of ptys
 * and utmp entries.
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * 
 *Permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#ifndef __LIBPTY_H__
#include <sys/types.h>
#include <utmp.h>

#ifdef __STDC__ /* use prototypes */

long pty_init(void);
long pty_getpty ( int *fd, char *slave, int slavelength);

long pty_open_slave (const char *slave, int *fd);
long pty_open_ctty (const char *slave, int *fd);

long pty_initialize_slave ( int fd);
long pty_update_utmp (struct utmp *ut, char *user, char *line, char *host);

long pty_update_wtmp (struct utmp *ut);
long pty_logwtmp (char *tty, char * user, char *host);

long pty_cleanup(char *slave, int pid, int update_utmp);
#else /*__STDC__*/
long pty_init();
long pty_getpty();

long pty_open_slave();
long pty_open_ctty();
long pty_initialize_slave();

long pty_update_utmp();
long pty_utmp_wtmp();
long pty_logwtmp();
long pty_cleanup();
#endif /* __STDC__*/
#define __LIBPTY_H__
#endif
