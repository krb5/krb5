/*
 * lib/krb5/os/lock_file.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * libos: krb5_lock_file routine
 */

#include "k5-int.h"
#include <stdio.h>

#if !defined(_MSDOS) && !defined(_WIN32) && !defined(HAVE_MACSOCK_H)

/* Unix version...  */

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef POSIX_FILE_LOCKS
#include <errno.h>
#include <fcntl.h>
#define SHARED_LOCK	F_RDLCK
#define EXCLUSIVE_LOCK	F_WRLCK
#define UNLOCK_LOCK	F_UNLCK
#else
#include <sys/file.h>
#define SHARED_LOCK	LOCK_SH
#define EXCLUSIVE_LOCK	LOCK_EX
#define UNLOCK_LOCK	LOCK_UN
#endif

extern int errno;

/*ARGSUSED*/
krb5_error_code
krb5_lock_file(context, fd, mode)
    krb5_context context;
    int fd;
    int mode;
{
#ifdef POSIX_FILE_LOCKS
    int lock_cmd = F_SETLKW;
    static struct flock flock_zero;
    struct flock lock_arg;
    lock_arg = flock_zero;
#define lock_flag lock_arg.l_type
    lock_flag = -1;
#else
    int lock_flag = -1;
#endif

    switch (mode & ~KRB5_LOCKMODE_DONTBLOCK) {
    case KRB5_LOCKMODE_SHARED:
	lock_flag = SHARED_LOCK;
	break;
    case KRB5_LOCKMODE_EXCLUSIVE:
	lock_flag = EXCLUSIVE_LOCK;
	break;
    case KRB5_LOCKMODE_UNLOCK:
	lock_flag = UNLOCK_LOCK;
	break;
    }

    if (lock_flag == -1)
	return(KRB5_LIBOS_BADLOCKFLAG);

    if (mode & KRB5_LOCKMODE_DONTBLOCK) {
#ifdef POSIX_FILE_LOCKS
	lock_cmd = F_SETLK;
#else
	lock_flag |= LOCK_NB;
#endif
    }

#ifdef POSIX_FILE_LOCKS
    lock_arg.l_whence = 0;
    lock_arg.l_start = 0;
    lock_arg.l_len = 0;
    if (fcntl(fd, lock_cmd, &lock_arg) == -1) {
	if (errno == EACCES || errno == EAGAIN)	/* see POSIX/IEEE 1003.1-1988,
						   6.5.2.4 */
	    return(EAGAIN);
	return(errno);
    }
#else
    if (flock(fd, lock_flag) == -1)
	return(errno);
#endif
    return 0;
}
#else   /* MSDOS or Macintosh */

krb5_error_code
krb5_lock_file(context, fd, mode)
    krb5_context context;
    int fd;
    int mode;
{
    return 0;
}
#endif
