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

#ifdef ultrix
#define ODBM
#endif

#define KRB5_USE_INET		/* Support IP address family */
#define	USE_DBM_LNAME		/* Use a DBM database for the aname/lname
				   conversion */

#define	DEFAULT_CONFIG_FILENAME	"/etc/krb.conf"
#define	DEFAULT_TRANS_FILENAME	"/etc/krb.realms"
#define	DEFAULT_LNAME_FILENAME	"/etc/aname"

#define KDC_PORTNAME	"kerberos5"	/* for /etc/services or equiv. */

#define MAX_DGRAM_SIZE	4096
#define MAX_SKDC_TIMEOUT 30
#define SKDC_TIMEOUT_SHIFT 2		/* left shift of timeout for backoff */
#define SKDC_TIMEOUT_1 1		/* seconds for first timeout */

#define RCTMPDIR	"/usr/tmp"	/* directory to store replay caches */
#define KDCRCACHE	"dfl:krb5kdc_rcache"

#ifdef POSIX_SIGTYPE
#define sigtype void
#else
typedef int sigtype;
#endif

#define BSDUNIX

#endif /* KRB5_OSCONF__ */
