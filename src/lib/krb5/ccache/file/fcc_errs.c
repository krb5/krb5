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
 * error code interpretation routine
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_errs_c [] =
"$Id$";
#endif	/* !lint & !SABER */


#include "fcc.h"

krb5_error_code
krb5_fcc_interpret(errnum)
int errnum;
{
    register int retval;
    switch (errnum) {
    case ENOENT:
	retval = KRB5_FCC_NOFILE;
	break;
    case EPERM:
    case EACCES:
    case EISDIR:
    case ENOTDIR:
#ifdef ELOOP
    case ELOOP:				/* XXX */
#endif
    case ETXTBSY:
    case EBUSY:
    case EROFS:
	retval = KRB5_FCC_PERM;
	break;
    case EINVAL:
    case EEXIST:			/* XXX */
    case EFAULT:
    case EBADF:
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
#endif
#ifdef EWOULDBLOCK
    case EWOULDBLOCK:
#endif
	retval = KRB5_FCC_INTERNAL;
	break;
#ifdef EDQUOT
    case EDQUOT:
#endif
    case ENOSPC:
    case EIO:
    case ENFILE:
    case EMFILE:
    case ENXIO:
    default:
	retval = KRB5_CC_IO;		/* XXX */
    }
    return retval;
}
