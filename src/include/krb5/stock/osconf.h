/*
 * include/krb5/stock/osconf.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Site- and OS- dependant configuration.
 */

#ifndef KRB5_OSCONF__
#define KRB5_OSCONF__

#ifndef KRB5_AUTOCONF__
#define KRB5_AUTOCONF__
#include "autoconf.h"
#endif

#define	USE_DBM_LNAME		/* Use a DBM database for the aname/lname
				   conversion */

#ifdef KRB5_ATHENA_COMPAT
#define	DEFAULT_CONFIG_FILENAME	"/etc/athena/krb.conf.v5"
#define	DEFAULT_TRANS_FILENAME	"/etc/athena/krb.realms"
#define	DEFAULT_LNAME_FILENAME	"/etc/athena/aname"
#define	DEFAULT_KEYTAB_NAME	"FILE:/etc/athena/v5srvtab"
#else
#define	DEFAULT_CONFIG_FILENAME	"@KRB5ROOT/krb.conf"
#define	DEFAULT_TRANS_FILENAME	"@KRB5ROOT/krb.realms"
#define	DEFAULT_LNAME_FILENAME	"@KRB5ROOT/aname"
#define	DEFAULT_KEYTAB_NAME	"FILE:@KRB5SRVTABDIR/v5srvtab"
#endif

#define DEFAULT_KDB_FILE        "@KDB5DIR/principal"
#define DEFAULT_ADMIN_ACL	"@KDB5DIR/admin_acl_file"

#define	DEFAULT_KDC_ETYPE	ETYPE_DES_CBC_CRC
#define	DEFAULT_KDC_KEYTYPE	KEYTYPE_DES
#define KDCRCACHE		"dfl:krb5kdc_rcache"

#define KDC_PORTNAME		"kerberos" /* for /etc/services or equiv. */
#define KDC_SECONDARY_PORTNAME	"kerberos-sec" /* For backwards */
					    /* compatibility with */
					    /* port 750 clients */

#define KRB5_DEFAULT_PORT	88
#define KRB5_DEFAULT_SEC_PORT	750

#define MAX_DGRAM_SIZE	4096
#define MAX_SKDC_TIMEOUT 30
#define SKDC_TIMEOUT_SHIFT 2		/* left shift of timeout for backoff */
#define SKDC_TIMEOUT_1 1		/* seconds for first timeout */

#define RCTMPDIR	"/usr/tmp"	/* directory to store replay caches */

#define KRB5_PATH_TTY	"/dev/tty"
#define KRB5_PATH_LOGIN	"@KRB5ROOT/sbin/login.krb5"
#define KRB5_PATH_RLOGIN "@KRB5ROOT/bin/rlogin"

#define KRB5_ENV_CCNAME	"KRB5CCNAME"

/*
 * krb4 kadmin stuff follows
 */

/* the default syslog file */
#define KADM_SYSLOG  "@KDB5DIR/admin_server.syslog"

/* where to find the bad password table */
#define PW_CHECK_FILE "@KDB5DIR/bad_passwd"

#define DEFAULT_ACL_DIR	"@KDB5DIR"
#endif /* KRB5_OSCONF__ */
