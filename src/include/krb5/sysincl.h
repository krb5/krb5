/*
 * $Source$
 * $Author$
 * $Id$
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
 * System include files, for various things.
 */


#ifndef KRB5_SYSINCL__
#define KRB5_SYSINCL__

#ifndef KRB5_SYSTYPES__
#define KRB5_SYSTYPES__
#include <sys/types.h>			/* needed for much of the reset */
#endif /* KRB5_SYSTYPES__ */

#include <krb5/osconf.h>		/* USE*TIME_H macros */
#ifdef USE_TIME_H
#include <time.h>
#endif
#ifdef USE_SYS_TIME_H
#include <sys/time.h>			/* struct timeval, utimes() */
#endif
#include <sys/stat.h>			/* struct stat, stat() */
#include <sys/param.h>			/* MAXPATHLEN */

#include <sys/file.h>			/* prototypes for file-related
					   syscalls; flags for open &
					   friends */
#ifndef L_SET
#define L_SET           0       /* absolute offset */
#define L_INCR          1       /* relative to current offset */
#define L_XTND          2       /* relative to end of file */
#endif /* L_SET */

#ifndef FD_SET
#define FD_SETSIZE          (sizeof (fd_set) * 8)

#define FD_SET(f,s)         ((s)->fds_bits[0] |= (1 << (f)))
#define FD_CLR(f,s)         ((s)->fds_bits[0] &= ~(1 << (f)))
#define FD_ISSET(f,s)       ((s)->fds_bits[0] & (1 << (f)))
#define FD_ZERO(s)          ((s)->fds_bits[0] = 0)
#endif

#if defined(SYSV) || defined(_AIX)
#include <fcntl.h>
#endif

#endif /* KRB5_SYSINCL__ */
