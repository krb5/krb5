/*
 * pty_update_utmp: Update or create a utmp entry
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
 * permission.  M.I.T. makes no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 * 
 */

#include <com_err.h>
#include "libpty.h"
#include "pty-int.h"

#if !defined(UTMP_FILE) && defined(_PATH_UTMP)
#define UTMP_FILE _PATH_UTMP
#endif

/* if it is *still* missing, assume SunOS */
#ifndef UTMP_FILE
#define	UTMP_FILE	"/etc/utmp"
#endif
#ifndef NO_UT_PID
#define WTMP_REQUIRES_USERNAME
#endif
long pty_update_utmp (process_type, pid, username, line, host, flags)
    int process_type;
    int pid;
    char *username, *line, *host;
    int flags;
{
    struct utmp ent, ut;
#ifndef HAVE_SETUTENT
    struct stat statb;
    int tty;
#endif
#ifdef HAVE_SETUTXENT
    struct utmpx utx;
#endif
#ifndef NO_UT_PID
    char *tmpx;
    char utmp_id[5];
#endif
    char userbuf[32];
    int fd;

    strncpy(ent.ut_line, line+sizeof("/dev/")-1, sizeof(ent.ut_line));
    ent.ut_time = time(0);
#ifdef NO_UT_PID
    if (process_type == PTY_LOGIN_PROCESS)
	return 0;
#else /* NO_UT_PID */
    ent.ut_pid = pid;
    switch (process_type) {
    case PTY_LOGIN_PROCESS:
	ent.ut_type = LOGIN_PROCESS;
	break;
    case PTY_USER_PROCESS:
	ent.ut_type = USER_PROCESS;
	break;
    case PTY_DEAD_PROCESS:
	ent.ut_type = DEAD_PROCESS;
	break;
    default:
	return PTY_UPDATE_UTMP_PROCTYPE_INVALID;
    }
#endif /*NO_UT_PID*/

#ifndef NO_UT_HOST
    if (host)
	strncpy(ent.ut_host, host, sizeof(ent.ut_host));
    else
	ent.ut_host[0] = '\0';
#endif

#ifndef NO_UT_PID
    if (!strcmp (line, "/dev/console"))
      strncpy (ent.ut_id, "cons", 4);
    else {
      tmpx = line + strlen(line)-1;
      if (*(tmpx-1) != '/') tmpx--; /* last two characters, unless it's a / */
#ifdef __hpux
      strcpy(utmp_id, tmpx);
#else
      sprintf(utmp_id, "kl%s", tmpx);
#endif
      strncpy(ent.ut_id, utmp_id, sizeof(ent.ut_id));
    }
    strncpy(ent.ut_user, username, sizeof(ent.ut_user));
#else
    strncpy(ent.ut_name, username, sizeof(ent.ut_name));
#endif
    if(username[0])
	strncpy(userbuf, username, sizeof(userbuf));
    else userbuf[0] = '\0';

#ifdef HAVE_SETUTENT

    utmpname(UTMP_FILE);
    setutent();
/* If we need to preserve the user name in the wtmp structure and
 * Our flags tell us we can obtain it from the utmp and we succeed in
 * obtaining it, we then save the utmp structure we obtain, write
 * out the utmp structure and change the username pointer so  it is used by
 * update_wtmp.*/
#ifdef WTMP_REQUIRES_USERNAME
    if (( !username[0]) && (flags&PTY_UTMP_USERNAME_VALID)
	&&line)  
	{
	  struct utmp *utptr;
	  strncpy(ut.ut_line, line, sizeof(ut.ut_line));
	  utptr = getutline(&ut);
	  if (utptr)
	    strncpy(userbuf,utptr->ut_user,sizeof(ut.ut_user));
	}
#endif

    pututline(&ent);
    endutent();
    
#ifdef HAVE_SETUTXENT
    setutxent();
#ifdef HAVE_GETUTMPX
    getutmpx(&ent, &utx);
#else
    /* For platforms like HPUX and Dec Unix which don't have getutmpx */
    strncpy(utx.ut_user, ent.ut_user, sizeof(ent.ut_user));
    strncpy(utx.ut_id, ent.ut_id, sizeof(ent.ut_id));
    strncpy(utx.ut_line, ent.ut_line, sizeof(ent.ut_line));
    utx.ut_pid = ent.ut_pid;
    utx.ut_type = ent.ut_type;
#ifdef UT_EXIT_STRUCTURE_DIFFER
    utx.ut_exit.ut_exit = ent.ut_exit.e_exit;
#else
/* KLUDGE for now; eventually this will be a feature test... See PR#[40] */
#ifdef __hpux	
    utx.ut_exit.__e_termination = ent.ut_exit.e_termination;
    utx.ut_exit.__e_exit = ent.ut_exit.e_exit;
#else
    utx.ut_exit = ent.ut_exit;
#endif
#endif
    utx.ut_tv.tv_sec = ent.ut_time;
    utx.ut_tv.tv_usec = 0;
#endif
    if (host)
      strncpy(utx.ut_host, host, sizeof(utx.ut_host));
    else
      utx.ut_host[0] = 0;
    pututxline(&utx);
    endutxent();
#endif /* HAVE_SETUTXENT */

#else /* HAVE_SETUTENT */
    if (flags&PTY_TTYSLOT_USABLE) 
	tty = ttyslot();
    else {
      int lc;
      tty = -1;
      if ((fd = open(UTMP_FILE, O_RDWR)) < 0)
	return errno;
      for (lc = 0;
	   lseek(fd, (off_t)(lc * sizeof(struct utmp)), SEEK_SET) != -1;
	   lc++) {
	if (read(fd, (char *) &ut, sizeof(struct utmp)) != sizeof(struct utmp))
	  break;
	if (strncmp(ut.ut_line, ent.ut_line, sizeof(ut.ut_line)) == 0) {
	  tty = lc;
#ifdef WTMP_REQUIRES_USERNAME
	  if (!username&&(flags&PTY_UTMP_USERNAME_VALID))
	    strncpy(userbuf, ut.ut_user, sizeof(ut.ut_user));
#endif
	  break;
	}
      }
      close(fd);
    }
    
    if (tty > 0 && (fd = open(UTMP_FILE, O_WRONLY, 0)) >= 0) {
      (void)lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
      (void)write(fd, (char *)&ent, sizeof(struct utmp));
      (void)close(fd);
    }


#endif /* HAVE_SETUTENT */

    /* Don't record LOGIN_PROCESS entries. */
    if (process_type == PTY_LOGIN_PROCESS)
      return 0;
    else
      return ptyint_update_wtmp(&ent, host, userbuf);
}
