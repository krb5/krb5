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

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)login.c	5.1 (Berkeley) 9/27/88";
#endif /* LIBC_SCCS and not lint */
     
#include <sys/types.h>
#include <sys/file.h>
#if defined (CRAY) || defined (sgi)
#include <sys/fcntl.h>
#define L_SET 0
#define L_INCR 1
#endif
#include <utmp.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
     
#ifndef UTMP_FILE
#define	UTMP_FILE	"/etc/utmp"
#endif
#ifndef WTMP_FILE
#ifdef SYSV
#define WTMPFILE    "/etc/wtmp"
#else
#define	WTMP_FILE	"/usr/adm/wtmp"
#endif
#endif
     
void login(ut)
     struct utmp *ut;
{
    register int fd;
    int tty;
    off_t lseek();
    
    tty = ttyslot();
    if (tty > 0 && (fd = open(UTMP_FILE, O_WRONLY, 0)) >= 0) {
	(void)lseek(fd, (long)(tty * sizeof(struct utmp)), L_SET);
	(void)write(fd, (char *)ut, sizeof(struct utmp));
	(void)close(fd);
    }
    if ((fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) >= 0) {
	(void)write(fd, (char *)ut, sizeof(struct utmp));
	(void)close(fd);
    }
}



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

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)logout.c	5.1 (Berkeley) 8/31/88";
#endif /* LIBC_SCCS and not lint */
     
logout(line)
     register char *line;
{
    register FILE *fp;
    struct utmp ut;
    int rval;
    time_t time();
    
    if (!(fp = fopen(UTMP_FILE, "r+")))
      return(0);
    rval = 1;
    while (fread((char *)&ut, sizeof(struct utmp), 1, fp) == 1) {
	if (!ut.ut_name[0] ||
	    strncmp(ut.ut_line, line, sizeof(ut.ut_line)))
	  continue;
	memset(ut.ut_name,0, sizeof(ut.ut_name));
#ifndef  NO_UT_HOST
	memset(ut.ut_host,0, sizeof(ut.ut_host));
#endif
	(void)time(&ut.ut_time);
	(void)fseek(fp, (long)-sizeof(struct utmp), L_INCR);
	(void)fwrite((char *)&ut, sizeof(struct utmp), 1, fp);
	(void)fseek(fp, (long)0, L_INCR);
	rval = 0;
    }
    (void)fclose(fp);
    return(rval);
}



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

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)logwtmp.c	5.2 (Berkeley) 9/20/88";
#endif /* LIBC_SCCS and not lint */
     
static int fd = -1;

#ifndef SYSV
logwtmp(line, name, host, keep_open)
#else
logwtmp(line, name, host, keep_open, logingin)
#endif
     char *line, *name, *host;
     int keep_open;
#ifdef  SYSV
     int logingin;
#endif
{
    struct utmp ut;
    struct stat buf;
    time_t time();
    char *strncpy();
    
    if (fd < 0 && (fd = open(WTMP_FILE, O_WRONLY|O_APPEND, 0)) < 0)
      return;
    if (!fstat(fd, &buf)) {
	(void)strncpy(ut.ut_line, line, sizeof(ut.ut_line));
	(void)strncpy(ut.ut_name, name, sizeof(ut.ut_name));
#ifndef  NO_UT_HOST
	(void)strncpy(ut.ut_host, host, sizeof(ut.ut_host));
#endif 
#ifdef  SYSV
	(void)strncpy(ut.ut_id, (char *)ut.ut_line + 4,
		      sizeof(ut.ut_id));
	ut.ut_type = logingin ? USER_PROCESS : DEAD_PROCESS;
	ut.ut_pid = getpid();
#endif
	(void)time(&ut.ut_time);
	if (write(fd, (char *)&ut, sizeof(struct utmp)) !=
	    sizeof(struct utmp))
	  (void)ftruncate(fd, buf.st_size);
    }
    if ( !keep_open)
      (void)close(fd);
}
