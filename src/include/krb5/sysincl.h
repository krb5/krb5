/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * System include files, for various things.
 */

#include <krb5/copyright.h>

#ifndef KRB5_SYSINCL__
#define KRB5_SYSINCL__

#include <sys/types.h>			/* needed for much of the reset */
#include <sys/time.h>			/* struct timeval, utimes() */
#include <sys/stat.h>			/* struct stat, stat() */
#include <sys/param.h>			/* MAXPATHLEN */
#if defined(unix) || defined(__unix__)
#include <sys/file.h>			/* prototypes for file-related
					   syscalls; flags for open &
					   friends */
#endif
#endif /* KRB5_SYSINCL__ */
