/*
 * lib/krb4/in_tkt.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000, 2001, 2007 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "krb.h"
#include <fcntl.h>
#include <sys/stat.h>
#include "autoconf.h"
#ifdef TKT_SHMEM
#include <sys/param.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

extern int krb_debug;

/*
 * in_tkt() is used to initialize the ticket store.  It creates the
 * file to contain the tickets and writes the given user's name "pname"
 * and instance "pinst" in the file.  in_tkt() returns KSUCCESS on
 * success, or KFAILURE if something goes wrong.
 */

#include "k5-util.h"
#define do_seteuid krb5_seteuid
#include "k5-platform.h"

#ifndef O_SYNC
#define O_SYNC 0
#endif

int KRB5_CALLCONV
in_tkt(pname,pinst)
    char *pname;
    char *pinst;
{
    int tktfile;
    uid_t me, metoo, getuid(), geteuid();
    struct stat statpre, statpost;
    int count;
    const char *file = TKT_FILE;
    int fd;
    register int i;
    char charbuf[BUFSIZ];
    mode_t mask;
#ifdef TKT_SHMEM
    char shmidname[MAXPATHLEN];
#endif /* TKT_SHMEM */

    /* If ticket cache selector is null, use default cache.  */
    if (file == 0)
	file = tkt_string();

    me = getuid ();
    metoo = geteuid();
    if (lstat(file, &statpre) == 0) {
	if (statpre.st_uid != me || !(statpre.st_mode & S_IFREG)
	    || statpre.st_nlink != 1 || statpre.st_mode & 077) {
	    if (krb_debug)
		fprintf(stderr,"Error initializing %s",file);
	    return(KFAILURE);
	}
	/*
	 * Yes, we do uid twiddling here.  It's not optimal, but some
	 * applications may expect that the ruid is what should really
	 * own the ticket file, e.g. setuid applications.
	 */
	if (me != metoo && do_seteuid(me) < 0)
	    return KFAILURE;
	/* file already exists, and permissions appear ok, so nuke it */
	fd = open(file, O_RDWR|O_SYNC, 0);
	if (fd >= 0)
	    set_cloexec_fd(fd);
	(void)unlink(file);
	if (me != metoo && do_seteuid(metoo) < 0)
	    return KFAILURE;
	if (fd < 0) {
	    goto out; /* can't zero it, but we can still try truncating it */
	}

	/*
	 * Do some additional paranoid things.  The worst-case
	 * situation is that a user may be fooled into opening a
	 * non-regular file briefly if the file is in a directory with
	 * improper permissions.
	 */
	if (fstat(fd, &statpost) < 0) {
	    (void)close(fd);
	    goto out;
	}
	if (statpre.st_dev != statpost.st_dev
	    || statpre.st_ino != statpost.st_ino) {
	    (void)close(fd);
	    errno = 0;
	    goto out;
	}

	memset(charbuf, 0, sizeof(charbuf));

	for (i = 0; i < statpost.st_size; i += sizeof(charbuf))
	    if (write(fd, charbuf, sizeof(charbuf)) != sizeof(charbuf)) {
#ifndef NO_FSYNC
		(void) fsync(fd);
#endif
		(void) close(fd);
		goto out;
	    }
	
#ifndef NO_FSYNC
	(void) fsync(fd);
#endif
	(void) close(fd);
    }
 out:
    /* arrange so the file is owned by the ruid
       (swap real & effective uid if necessary).
       This isn't a security problem, since the ticket file, if it already
       exists, has the right uid (== ruid) and mode. */
    if (me != metoo) {
	if (do_seteuid(me) < 0) {
	    /* can't switch??? barf! */
	    if (krb_debug)
		perror("in_tkt: seteuid");
	    return(KFAILURE);
	} else
	    if (krb_debug)
		printf("swapped UID's %d and %d\n",(int) metoo, (int) me);
    }
    /* Set umask to ensure that we have write access on the created
       ticket file.  */
    mask = umask(077);
    tktfile = open(file, O_RDWR|O_SYNC|O_CREAT|O_EXCL, 0600);
    if (tktfile >= 0)
	set_cloexec_fd(tktfile);
    umask(mask);
    if (me != metoo) {
	if (do_seteuid(metoo) < 0) {
	    /* can't switch??? barf! */
	    if (krb_debug)
		perror("in_tkt: seteuid2");
	    return(KFAILURE);
	} else
	    if (krb_debug)
		printf("swapped UID's %d and %d\n", (int) me, (int) metoo);
    }
    if (tktfile < 0) {
	if (krb_debug)
	    fprintf(stderr,"Error initializing %s",TKT_FILE);
        return(KFAILURE);
    }
    count = strlen(pname)+1;
    if (write(tktfile,pname,count) != count) {
        (void) close(tktfile);
        return(KFAILURE);
    }
    count = strlen(pinst)+1;
    if (write(tktfile,pinst,count) != count) {
        (void) close(tktfile);
        return(KFAILURE);
    }
    (void) close(tktfile);
#ifdef TKT_SHMEM
    (void) strncpy(shmidname, file, sizeof(shmidname) - 1);
    shmidname[sizeof(shmidname) - 1] = '\0';
    (void) strncat(shmidname, ".shm", sizeof(shmidname) - 1 - strlen(shmidname));
    return(krb_shm_create(shmidname));
#else /* !TKT_SHMEM */
    return(KSUCCESS);
#endif /* TKT_SHMEM */
}

int KRB5_CALLCONV
krb_in_tkt(pname, pinst, prealm)
    char *pname;
    char *pinst;
    char *prealm;
{
    return in_tkt(pname, pinst);
}
