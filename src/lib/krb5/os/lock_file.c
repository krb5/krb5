/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * libos: krb5_lock_file routine
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_lock_file_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/libos.h>

#include <stdio.h>

/* POSIX_* are auto-magically defined in <krb5/config.h> at source
   configuration time. */

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

#include <sys/types.h>
#include <krb5/ext-proto.h>

extern int errno;

/*ARGSUSED*/
krb5_error_code
krb5_lock_file(filep, pathname, mode)
FILE *filep;
char *pathname;
int mode;
{
#ifdef POSIX_FILE_LOCKS
    int lock_cmd = F_SETLKW;
    struct flock lock_arg;
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
    if (fcntl(fileno(filep), lock_cmd, &lock_arg) == -1) {
	if (errno == EACCES || errno == EAGAIN)	/* see POSIX/IEEE 1003.1-1988,
						   6.5.2.4 */
	    return(EAGAIN);
	return(errno);
    }
#else
    if (flock(fileno(filep), lock_flag) == -1)
	return(errno);
#endif
    return 0;
}
