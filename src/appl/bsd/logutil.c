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
     
#ifndef EMPTY
/* linux has UT_UNKNOWN but not EMPTY */
#define EMPTY UT_UNKNOWN
#endif

void update_utmp();
void update_wtmp();
void logwtmp();

void update_utmp(ent, username, line, host)
    struct utmp *ent;
    char *username, *line, *host;
{
    char *tmpx;
#ifdef HAVE_SETUTENT
    struct utmp ut;
    char utmp_id[5];
#else
    struct stat statb;
#endif
#ifdef HAVE_SETUTXENT
    struct utmpx utx;
#endif
    
    strncpy(ent->ut_line, line+sizeof("/dev/")-1, sizeof(ent->ut_line));
    ent->ut_time = time(0);

#ifndef NO_UT_HOST
    if (host)
	strncpy(ent->ut_host, host, sizeof(ent->ut_host));
    else
	ent->ut_host[0] = '\0';
#endif

#ifdef HAVE_SETUTENT
    tmpx = line + strlen(line)-1;
    if (*(tmpx-1) != '/') tmpx--; /* last two characters, unless it's a / */
    sprintf(utmp_id, "kl%s", tmpx);
    strncpy(ent->ut_id, utmp_id, sizeof(ent->ut_id));
    strncpy(ent->ut_user, username, sizeof(ent->ut_user));
#else
    strncpy(ent->ut_name, username, sizeof(ent->ut_name));
#endif
    
#ifdef HAVE_SETUTXENT
    getutmpx(ent, &utx);
    getutxid(&utx);
    setutxent();
    pututxline(&utx);
    endutxent();
#endif
#ifdef HAVE_SETUTENT
    utmpname(UTMP_FILE);
    setutent();
    getutid(ent);
    pututline(ent);
    endutent();
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
    
#ifdef HAVE_SETUTENT
    strncpy(ut.ut_user, locuser, sizeof(ut.ut_user));

    tmpx = tty + strlen(tty) - 2;
    sprintf(utmp_id, "kr%s", tmpx);
    strncpy(ut.ut_id, utmp_id, sizeof(ut.ut_id));

#ifndef NO_UT_TYPE
    ut.ut_type = (loggingin ? USER_PROCESS : DEAD_PROCESS);
#endif
#ifndef NO_UT_PID
    ut.ut_pid = (loggingin ? getpid() : 0);
#endif
#endif

    update_wtmp(&ut);
}
