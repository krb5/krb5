/*
 * krb5_seteuid: Attempt to set the effective user ID of the current process
 * in such a way it can be restored lated.
 *
 * Copyright 1996 by the Massachusetts Institute of Technology.
 *
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * M.I.T. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 * 
 */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <k5-int.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif


#include <errno.h>

int krb5_seteuid( euid_in)
  int euid_in;
{
  uid_t euid = (uid_t) euid_in;
#if defined(_POSIX_SAVED_IDS) && defined(HAVE_SETEUID)
  return  (seteuid(euid)) ;
#else
#if defined(HAVE_SETRESUID)
    return (setresuid(getuid(), euid, geteuid())) ;
#else
#if defined(HAVE_SETREUID)
    return setreuid(geteuid(), euid); 
#else /*HAVE_SETREUID*/
    /* You need to add a case to deal with this operating system.*/
    errno = EPERM;
  return -1;
  
#endif /* HAVE_SETREUID */
#endif /* HAVE_SETRESUID */
#endif /* _POSIX_SAVED_IDS */


}
