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

#ifndef KRB5_OSCONF__
#define KRB5_OSCONF__

#define KRB5_USE_INET		/* Support IP address family */

#define	DEFAULT_CONFIG_FILENAME	"/etc/krb.conf"
#define KDC_PORTNAME	"kerberos5"	/* for /etc/services or equiv. */

#ifdef POSIX_SIGTYPE
#define sigtype void
#else
typedef int sigtype;
#endif

#endif /* KRB5_OSCONF__ */
