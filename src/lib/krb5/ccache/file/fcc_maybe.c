/*
 * lib/krb5/ccache/file/fcc_maybe.c
 *
 * Copyright 1990, 1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for conditional open/close calls.
 */

#define NEED_SOCKETS    /* Only for ntohs, etc. */
#define NEED_LOWLEVEL_IO
#include "k5-int.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
          
#include "fcc.h"

int krb5_fcc_default_format = KRB5_FCC_DEFAULT_FVNO;

#ifdef KRB5_USE_INET
#if !defined(_WINSOCKAPI_) && !defined(HAVE_MACSOCK_H)
#include <netinet/in.h>
#endif
#else
 #error find some way to use net-byte-order file version numbers.
#endif

#include <stdio.h>

#define LOCK_IT 0
#define UNLOCK_IT 1

/* Under SunOS 4 and SunOS 5 and possibly other operating systems, having
   POSIX fcntl locks doesn't mean that they work on every filesystem. If we
   get EINVAL, try flock (if we have it) since that might work... */

#ifdef POSIX_FILE_LOCKS
static krb5_error_code fcc_lock_file_posix PROTOTYPE((krb5_fcc_data *, int, int));

#ifndef unicos61
#include <fcntl.h>
#endif /* unicos61 */

#define SHARED_LOCK	F_RDLCK
#define EXCLUSIVE_LOCK	F_WRLCK
#define UNLOCK_LOCK	F_UNLCK

static krb5_error_code
fcc_lock_file_posix(data, fd, lockunlock)
krb5_fcc_data *data;
int fd;
int lockunlock;
{
    /* XXX need to in-line lock_file.c here, but it's sort-of OK since
       we're already unix-dependent for file descriptors */

    int lock_cmd = F_SETLKW;
    struct flock lock_arg;
#define lock_flag lock_arg.l_type
    lock_flag = -1;

    if (lockunlock == LOCK_IT)
	switch (data->mode) {
	case FCC_OPEN_RDONLY:
	    lock_flag = SHARED_LOCK;
	    break;
	case FCC_OPEN_RDWR:
	case FCC_OPEN_AND_ERASE:
	    lock_flag = EXCLUSIVE_LOCK;
	    break;
	}
    else
	lock_flag = UNLOCK_LOCK;

    if (lock_flag == -1)
	return(KRB5_LIBOS_BADLOCKFLAG);

    lock_arg.l_whence = 0;
    lock_arg.l_start = 0;
    lock_arg.l_len = 0;
    if (fcntl(fd, lock_cmd, &lock_arg) == -1) {
	if (errno == EACCES || errno == EAGAIN)	/* see POSIX/IEEE 1003.1-1988,
						   6.5.2.4 */
	    return(EAGAIN);
	return(errno);
    }
    return 0;
}
#undef lock_flag

#undef SHARED_LOCK
#undef EXCLUSIVE_LOCK
#undef UNLOCK_LOCK

#endif /* POSIX_FILE_LOCKS */

#ifdef HAVE_FLOCK

#ifndef sysvimp
#include <sys/file.h>
#endif /* sysvimp */

#define SHARED_LOCK	LOCK_SH
#define EXCLUSIVE_LOCK	LOCK_EX
#define UNLOCK_LOCK	LOCK_UN

static krb5_error_code fcc_lock_file_flock PROTOTYPE((krb5_fcc_data *, int, int));
static krb5_error_code
fcc_lock_file_flock(data, fd, lockunlock)
krb5_fcc_data *data;
int fd;
int lockunlock;
{
    /* XXX need to in-line lock_file.c here, but it's sort-of OK since
       we're already unix-dependent for file descriptors */

    int lock_flag = -1;

    if (lockunlock == LOCK_IT)
	switch (data->mode) {
	case FCC_OPEN_RDONLY:
	    lock_flag = SHARED_LOCK;
	    break;
	case FCC_OPEN_RDWR:
	case FCC_OPEN_AND_ERASE:
	    lock_flag = EXCLUSIVE_LOCK;
	    break;
	}
    else
	lock_flag = UNLOCK_LOCK;

    if (lock_flag == -1)
	return(KRB5_LIBOS_BADLOCKFLAG);

    if (flock(fd, lock_flag) == -1)
	return(errno);
    return 0;
}

#undef SHARED_LOCK
#undef EXCLUSIVE_LOCK
#undef UNLOCK_LOCK

#endif /* HAVE_FLOCK */

static krb5_error_code fcc_lock_file PROTOTYPE((krb5_fcc_data *, int, int));
static krb5_error_code
fcc_lock_file(data, fd, lockunlock)
krb5_fcc_data *data;
int fd;
int lockunlock;
{
  krb5_error_code st = 0;
#ifdef POSIX_FILE_LOCKS
  st = fcc_lock_file_posix(data, fd, lockunlock);
  if (st != EINVAL) {
    return st;
  }
#endif /* POSIX_FILE_LOCKS */

#ifdef HAVE_FLOCK
  return fcc_lock_file_flock(data, fd, lockunlock);
#else
  return st;
#endif
}

krb5_error_code
krb5_fcc_close_file (context, id)
   krb5_context context;
    krb5_ccache id;
{
     int ret;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code retval;

     if (data->fd == -1)
	 return KRB5_FCC_INTERNAL;

     retval = fcc_lock_file(data, data->fd, UNLOCK_IT);
     ret = close (data->fd);
     data->fd = -1;
     if (retval)
	 return retval;
     else
     return (ret == -1) ? krb5_fcc_interpret (context, errno) : 0;
}

krb5_error_code
krb5_fcc_open_file (context, id, mode)
   krb5_context context;
    krb5_ccache id;
    int mode;
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_ui_2 fcc_fvno;
     int fd;
     int open_flag;
     krb5_error_code retval = 0;

     if (data->fd != -1) {
	  /* Don't know what state it's in; shut down and start anew.  */
	  (void) fcc_lock_file(data, data->fd, UNLOCK_IT);
	  (void) close (data->fd);
	  data->fd = -1;
     }
     data->mode = mode;
     switch(mode) {
     case FCC_OPEN_AND_ERASE:
	 open_flag = O_CREAT|O_TRUNC|O_RDWR;
	 break;
     case FCC_OPEN_RDWR:
	 open_flag = O_RDWR;
	 break;
     case FCC_OPEN_RDONLY:
     default:
	 open_flag = O_RDONLY;
	 break;
     }

     fd = THREEPARAMOPEN (data->filename, open_flag | O_BINARY, 0600);
     if (fd == -1)
	  return krb5_fcc_interpret (context, errno);

     if ((retval = fcc_lock_file(data, fd, LOCK_IT))) {
	 (void) close(fd);
	 return retval;
     }
	 
     if (mode == FCC_OPEN_AND_ERASE) {
	 /* write the version number */
	 int errsave, cnt;

	 fcc_fvno = htons(krb5_fcc_default_format);
	 data->version = krb5_fcc_default_format;
	 if ((cnt = write(fd, (char *)&fcc_fvno, sizeof(fcc_fvno))) !=
	     sizeof(fcc_fvno)) {
	     errsave = errno;
	     (void) fcc_lock_file(data, fd, UNLOCK_IT);
	     (void) close(fd);
	     return (cnt == -1) ? krb5_fcc_interpret(context, errsave) : KRB5_CC_IO;
	 }
     } else {
	 /* verify a valid version number is there */
	 if (read(fd, (char *)&fcc_fvno, sizeof(fcc_fvno)) !=
	     sizeof(fcc_fvno)) {
	     (void) fcc_lock_file(data, fd, UNLOCK_IT);
	     (void) close(fd);
	     return KRB5_CCACHE_BADVNO;
	 }
	 if ((fcc_fvno != htons(KRB5_FCC_FVNO_3)) &&
	     (fcc_fvno != htons(KRB5_FCC_FVNO_2)) &&
	     (fcc_fvno != htons(KRB5_FCC_FVNO_1))) {
	     (void) fcc_lock_file(data, fd, UNLOCK_IT);
	     (void) close(fd);
	     return KRB5_CCACHE_BADVNO;
	 }
	 data->version = ntohs(fcc_fvno);
     }
     data->fd = fd;
     return 0;
}
