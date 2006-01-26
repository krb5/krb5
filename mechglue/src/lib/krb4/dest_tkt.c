/*
 * lib/krb4/dest_tkt.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2000, 2001 by the Massachusetts
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

#include "krb.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "k5-util.h"
#define do_seteuid krb5_seteuid

#ifdef TKT_SHMEM
#include <sys/param.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>

#ifndef O_SYNC
#define O_SYNC 0
#endif

/*
 * dest_tkt() is used to destroy the ticket store upon logout.
 * If the ticket file does not exist, dest_tkt() returns RET_TKFIL.
 * Otherwise the function returns RET_OK on success, KFAILURE on
 * failure.
 *
 * The ticket file (TKT_FILE) is defined in "krb.h".
 */

int KRB5_CALLCONV
dest_tkt()
{
    const char *file = TKT_FILE;
    int i,fd;
    int ret;
    struct stat statpre, statpost;
    char buf[BUFSIZ];
    uid_t me, metoo;
#ifdef TKT_SHMEM
    char shmidname[MAXPATHLEN];
    size_t shmidlen;
#endif /* TKT_SHMEM */

    /* If ticket cache selector is null, use default cache.  */
    if (file == 0)
	file = tkt_string();

    errno = 0;
    ret = KSUCCESS;
    me = getuid();
    metoo = geteuid();

    if (lstat(file, &statpre) < 0)
	return (errno == ENOENT) ? RET_TKFIL : KFAILURE;
    /*
     * This does not guard against certain cases that are vulnerable
     * to race conditions, such as world-writable or group-writable
     * directories that are not stickybitted, or untrusted path
     * components.  In all other cases, the following checks should be
     * sufficient.  It is assumed that the aforementioned certain
     * vulnerable cases are unlikely to arise on a well-administered
     * system where the user is not deliberately being stupid.
     */
    if (!(statpre.st_mode & S_IFREG) || me != statpre.st_uid
	|| statpre.st_nlink != 1)
	return KFAILURE;
    /*
     * Yes, we do uid twiddling here.  It's not optimal, but some
     * applications may expect that the ruid is what should really own
     * the ticket file, e.g. setuid applications.
     */
    if (me != metoo && do_seteuid(me) < 0)
	return KFAILURE;
    if ((fd = open(file, O_RDWR|O_SYNC, 0)) < 0) {
	ret = (errno == ENOENT) ? RET_TKFIL : KFAILURE;
	goto out;
    }
    /*
     * Do some additional paranoid things.  The worst-case situation
     * is that a user may be fooled into opening a non-regular file
     * briefly if the file is in a directory with improper
     * permissions.
     */
    if (fstat(fd, &statpost) < 0) {
	(void)close(fd);
	ret = KFAILURE;
	goto out;
    }
    if (statpre.st_dev != statpost.st_dev
	|| statpre.st_ino != statpost.st_ino) {
	(void)close(fd);
	errno = 0;
	ret = KFAILURE;
	goto out;
    }

    memset(buf, 0, BUFSIZ);
    for (i = 0; i < statpost.st_size; i += BUFSIZ)
	if (write(fd, buf, BUFSIZ) != BUFSIZ) {
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

    (void) unlink(file);

out:
    if (me != metoo && do_seteuid(metoo) < 0)
	return KFAILURE;
    if (ret != KSUCCESS)
	return ret;

#ifdef TKT_SHMEM
    /* 
     * handle the shared memory case 
     */
    shmidlen = strlen(file) + sizeof(".shm");
    if (shmidlen > sizeof(shmidname))
	return RET_TKFIL;
    (void)strcpy(shmidname, file);
    (void)strcat(shmidname, ".shm");
    return krb_shm_dest(shmidname);
#else  /* !TKT_SHMEM */
    return KSUCCESS;
#endif /* !TKT_SHMEM */
}
