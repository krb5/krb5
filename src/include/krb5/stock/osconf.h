/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Site- and OS- dependant configuration.
 * This is mostly a stub.
 */

#include <krb5/copyright.h>

#ifndef __krb5_osconf__
#define __krb5_osconf__

#define KRB5_USE_INET		/* Support IP address family */


#ifdef POSIX_SIGTYPE
#define sigtype void
#else
typedef int sigtype;
#endif

#endif /* __krb5_osconf__ */
