/*
 * Header file for manipulation of ptys and utmp entries.
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 *
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
 * 
 */

#ifndef __LIBPTY_H__

/* Constants for pty_update_utmp */
#define PTY_LOGIN_PROCESS 0
#define PTY_USER_PROCESS 1
#define PTY_DEAD_PROCESS 2

/* flags to update_utmp*/
#define PTY_TTYSLOT_USABLE (0x1)
#define PTY_UTMP_USERNAME_VALID (0x2)

long pty_init(void);
long pty_getpty ( int *fd, char *slave, int slavelength);

long pty_open_slave (const char *slave, int *fd);
long pty_open_ctty (const char *slave, int *fd);

long pty_initialize_slave ( int fd);
long pty_update_utmp(int process_type, int pid, const char *user,
		     const char *tty_line, const char *host, int flags);

long pty_logwtmp(const char *tty, const char *user, const char *host);

long pty_cleanup(char *slave, int pid, int update_utmp);

#ifndef SOCK_DGRAM
struct sockaddr;
#endif

long pty_make_sane_hostname(const struct sockaddr *, int, int, int, char **);
#define __LIBPTY_H__
#endif
