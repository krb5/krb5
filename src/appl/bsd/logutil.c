/*
 * Copyright (c) 1988 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#include <sys/file.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <utmp.h>
#ifdef HAVE_SETUTXENT
#include <utmpx.h>
#endif

#ifndef UTMP_FILE
#define	UTMP_FILE	"/etc/utmp"
#endif
#ifndef WTMP_FILE
#define	WTMP_FILE	"/usr/adm/wtmp"
#endif
     

void update_utmp();
void update_wtmp();
void logwtmp();


void update_utmp(ent, username, line, host)
    struct utmp *ent;
    char *username, *line, *host;
{
#ifdef HAVE_SETUTENT
    struct utmp ut;
#else
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
    int fd;

    strncpy(ent->ut_line, line+sizeof("/dev/")-1, sizeof(ent->ut_line));
    ent->ut_time = time(0);

#ifndef NO_UT_HOST
    if (host)
	strncpy(ent->ut_host, host, sizeof(ent->ut_host));
    else
	ent->ut_host[0] = '\0';
#endif

#ifndef NO_UT_PID
    tmpx = line + strlen(line)-1;
    if (*(tmpx-1) != '/') tmpx--; /* last two characters, unless it's a / */
    sprintf(utmp_id, "kl%s", tmpx);
    strncpy(ent->ut_id, utmp_id, sizeof(ent->ut_id));
    strncpy(ent->ut_user, username, sizeof(ent->ut_user));
#else
    strncpy(ent->ut_name, username, sizeof(ent->ut_name));
#endif
    
#ifdef HAVE_SETUTENT

    utmpname(UTMP_FILE);
    setutent();
    pututline(ent);
    endutent();

#if 0
    /* XXX -- NOT NEEDED ANYMORE */

    if (ent->ut_type == DEAD_PROCESS) {
	if ((fd = open(UTMP_FILE, O_RDWR)) >= 0) {
	    int cnt = 0;
	    while(read(fd, (char *)&ut, sizeof(ut)) == sizeof(ut)) {
		if (!strncmp(ut.ut_id, ent->ut_id, sizeof(ut.ut_id))) {
		    (void) memset(ut.ut_host, 0, sizeof(ut.ut_host));
		    (void) memset(ut.ut_user, 0, sizeof(ut.ut_user));
		    (void) time(&ut.ut_time);
		    ut.ut_exit.e_exit = ut.ut_pid = 0;
		    ut.ut_type = EMPTY;
		    (void) lseek(fd, -sizeof(ut), SEEK_CUR);
		    (void) write(fd, &ut, sizeof(ut));
		}
		cnt++;
	    }
	    close(fd);
	}
    }
#endif
    
#ifdef HAVE_SETUTXENT
    setutxent();
    getutmpx(ent, &utx);
    pututxline(&utx);
    endutxent();
#endif /* HAVE_SETUTXENT */

#else /* HAVE_SETUTENT */
	
    tty = ttyslot();
    if (tty > 0 && (fd = open(UTMP_FILE, O_WRONLY, 0)) >= 0) {
	(void)lseek(fd, (off_t)(tty * sizeof(struct utmp)), SEEK_SET);
	(void)write(fd, (char *)ent, sizeof(struct utmp));
	(void)close(fd);
    }

#endif /* HAVE_SETUTENT */

    update_wtmp(ent);
}

void update_wtmp(ent)
    struct utmp *ent;
{
#ifndef HAVE_SETUTENT
    struct utmp ut;
    struct stat statb;
    int fd;
#endif /* !HAVE_SETUTENT */
#ifdef HAVE_SETUTXENT
    struct utmpx utx;

    getutmpx(ent, &utx);
    updwtmpx(WTMPX_FILE, &utx);
#endif

#ifdef HAVE_UPDWTMP
    updwtmp(WTMP_FILE, ent);
#else /* HAVE_UPDWTMP */
#ifdef HAVE_SETUTENT
    utmpname(WTMP_FILE);
    setutent();
    pututline(ent);
    endutent();
#else /* HAVE_SETUTENT */

    if ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) >= 0) {
	if (!fstat(fd, &statb)) {
	  (void)memset((char *)&ut, 0, sizeof(ut));
	  (void)strncpy(ut.ut_line, ent->ut_line, sizeof(ut.ut_line));
	  (void)strncpy(ut.ut_name, ent->ut_name, sizeof(ut.ut_name));
#ifndef NO_UT_HOST
	  (void)strncpy(ut.ut_host, ent->ut_host, sizeof(ut.ut_host));
#endif
	  (void)time(&ut.ut_time);
#ifdef HAVE_GETUTENT
	  if (ent->ut_name) {
	    if (!ut.ut_pid)
	      ut.ut_pid = getpid();
	    ut.ut_type = USER_PROCESS;
	  } else {
	    ut.ut_type = EMPTY;
	  }
#endif
	    if (write(fd, (char *)&ut, sizeof(struct utmp)) !=
		sizeof(struct utmp))
	      (void)ftruncate(fd, statb.st_size);
	}
	(void)close(fd);
    }
#endif /* HAVE_SETUTENT */
#endif /* HAVE_UPDWTMP */
}

void logwtmp(tty, locuser, host, loggingin)
    char *tty;
    char *locuser;
    char *host;
    int loggingin;
{
    struct utmp ut;
    char *tmpx;
    char utmp_id[5];

#ifndef NO_UT_HOST
    strncpy(ut.ut_host, host, sizeof(ut.ut_host));
#endif

    strncpy(ut.ut_line, tty, sizeof(ut.ut_line));
    ut.ut_time = time(0);
    
#ifndef NO_UT_PID
    ut.ut_pid = getpid();
    strncpy(ut.ut_user, locuser, sizeof(ut.ut_user));

    tmpx = tty + strlen(tty) - 2;
    sprintf(utmp_id, "kr%s", tmpx);
    strncpy(ut.ut_id, utmp_id, sizeof(ut.ut_id));
    ut.ut_pid = (loggingin ? getpid() : 0);
    ut.ut_type = (loggingin ? USER_PROCESS : DEAD_PROCESS);
#else
    strncpy(ut.ut_name, locuser, sizeof(ut.ut_name));
#endif

    update_wtmp(&ut);
}
