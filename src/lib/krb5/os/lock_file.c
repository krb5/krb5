/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * libos: krb5_lock_file routine
 */

#ifndef	lint
static char rcsid_lock_file_c [] =
"$Id$";
#endif	lint

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/libos.h>

#include <stdio.h>
#include <sys/file.h>

extern int errno;

krb5_error_code
krb5_lock_file(filep, mode)
FILE *filep;
int mode;
{
    int flock_flag = -1;

    switch (mode & ~KRB5_LOCKMODE_DONTBLOCK) {
    case KRB5_LOCKMODE_SHARED:
	flock_flag = LOCK_SH;
    case KRB5_LOCKMODE_EXCLUSIVE:
	flock_flag = LOCK_EX;
    case KRB5_LOCKMODE_UNLOCK:
	flock_flag = LOCK_UN;
    }
    if (flock_flag == -1)
	return(KRB5_LIBOS_BADLOCKFLAG);
    if (mode & KRB5_LOCKMODE_DONTBLOCK)
	flock_flag |= LOCK_NB;

    if (flock(fileno(filep), flock_flag) == -1)
	return(errno);
    return 0;
}
