/*
 * $Source$
 * $Author$
 *
 * Copyright 1990, 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for conditional open/close calls.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_maybe_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "fcc.h"
#include <netinet/in.h>			/* XXX ip only? */
#include <krb5/libos.h>
#include <krb5/los-proto.h>
#include <stdio.h>

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

#define LOCK_IT 0
#define UNLOCK_IT 1

static krb5_error_code fcc_lock_file PROTOTYPE((krb5_fcc_data *,
						int, int));

static krb5_error_code
fcc_lock_file(data, fd, lockunlock)
krb5_fcc_data *data;
int fd;
int lockunlock;
{
    /* XXX need to in-line lock_file.c here, but it's sort-of OK since
       we're already unix-dependent for file descriptors */

#ifdef POSIX_FILE_LOCKS
    int lock_cmd = F_SETLKW;
    struct flock lock_arg;
#define lock_flag lock_arg.l_type
    lock_flag = -1;
#else
    int lock_flag = -1;
#endif

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

krb5_error_code
krb5_fcc_close_file (id)
    krb5_ccache id;
{
     int ret;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code retval;

     if (data->fd == -1) {
	 abort ();			/* XXX? */
     }
     retval = fcc_lock_file(data, data->fd, UNLOCK_IT);
     ret = close (data->fd);
     data->fd = -1;
     if (retval)
	 return retval;
     else
     return (ret == -1) ? krb5_fcc_interpret (errno) : 0;
}

krb5_error_code
krb5_fcc_open_file (id, mode)
    krb5_ccache id;
    int mode;
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_int16 fcc_fvno = htons(KRB5_FCC_FVNO);
     int fd;
     int open_flag;
     krb5_error_code retval;

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

     fd = open (data->filename, open_flag, 0600);
     if (fd == -1)
	  return krb5_fcc_interpret (errno);

     if (retval = fcc_lock_file(data, fd, LOCK_IT)) {
	 (void) close(fd);
	 return retval;
     }
	 
     if (mode == FCC_OPEN_AND_ERASE) {
	 /* write the version number */
	 int errsave, cnt;

	 if ((cnt = write(fd, (char *)&fcc_fvno, sizeof(fcc_fvno))) !=
	     sizeof(fcc_fvno)) {
	     errsave = errno;
	     (void) fcc_lock_file(data, fd, UNLOCK_IT);
	     (void) close(fd);
	     return (cnt == -1) ? krb5_fcc_interpret(errsave) : KRB5_CC_IO;
	 }
     } else {
	 /* verify a valid version number is there */
	 if (read(fd, (char *)&fcc_fvno, sizeof(fcc_fvno)) !=
	     sizeof(fcc_fvno)) {
	     (void) fcc_lock_file(data, fd, UNLOCK_IT);
	     (void) close(fd);
	     return KRB5_CCACHE_BADVNO;
	 }
	 if (fcc_fvno != htons(KRB5_FCC_FVNO)) {
	     (void) fcc_lock_file(data, fd, UNLOCK_IT);
	     (void) close(fd);
	     return KRB5_CCACHE_BADVNO;
	 }
     }
     data->fd = fd;
     return 0;
}
