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

#if !defined(_MSDOS)
    /* Don't try to pull in autoconf.h for Windows, since it's not used */
#ifndef KRB5_AUTOCONF__
#define KRB5_AUTOCONF__
#include "autoconf.h"
#endif
#endif

#if defined(_WINDOWS) || defined(WIN32)
#define DEFAULT_PROFILE_FILENAME "krb5.ini"
#define	DEFAULT_LNAME_FILENAME	"/aname"
#define	DEFAULT_KEYTAB_NAME	"FILE:%s\\v5srvtab"
#else /* !_WINDOWS */
#define DEFAULT_PROFILE_PATH "/etc/krb5.conf:@PREFIX/lib/krb5.conf"
#define	DEFAULT_KEYTAB_NAME	"FILE:/etc/v5srvtab"
#define	DEFAULT_LNAME_FILENAME	"@PREFIX/lib/krb5.aname"
#endif /* _WINDOWS  */

#define DEFAULT_KDB_FILE        "@PREFIX/lib/krb5kdc/principal"
#define	DEFAULT_KEYFILE_STUB	"@PREFIX/lib/krb5kdc/.k5."
#define KRB5_DEFAULT_ADMIN_ACL	"@PREFIX/lib/krb5kdc/krb5_adm.acl"
/* Used by old admin server */
#define	DEFAULT_ADMIN_ACL	"@PREFIX/lib/krb5kdc/kadm_old.acl"

/* Location of KDC profile */
#define	DEFAULT_KDC_PROFILE	"@PREFIX/lib/krb5kdc/kdc.conf"
#define	KDC_PROFILE_ENV		"KRB5_KDC_PROFILE"

#define	DEFAULT_KDC_ENCTYPE	ENCTYPE_DES_CBC_CRC
#define KDCRCACHE		"dfl:krb5kdc_rcache"

#define KDC_PORTNAME		"kerberos" /* for /etc/services or equiv. */
#define KDC_SECONDARY_PORTNAME	"kerberos-sec" /* For backwards */
					    /* compatibility with */
					    /* port 750 clients */

#define KRB5_DEFAULT_PORT	88
#define KRB5_DEFAULT_SEC_PORT	750

#define DEFAULT_KDC_PORTLIST	"88,750"

#define MAX_DGRAM_SIZE	4096
#define MAX_SKDC_TIMEOUT 30
#define SKDC_TIMEOUT_SHIFT 2		/* left shift of timeout for backoff */
#define SKDC_TIMEOUT_1 1		/* seconds for first timeout */

#define RCTMPDIR	"@KRB5RCTMPDIR"	/* directory to store replay caches */

#define KRB5_PATH_TTY	"/dev/tty"
#define KRB5_PATH_LOGIN	"@EXEC_PREFIX/sbin/login.krb5"
#define KRB5_PATH_RLOGIN "@EXEC_PREFIX/bin/rlogin"

#define KRB5_ENV_CCNAME	"KRB5CCNAME"

/*
 * krb4 kadmin stuff follows
 */

/* the default syslog file */
#define KADM_SYSLOG  "@PREFIX/lib/krb5kdc/admin_server.syslog"

/* where to find the bad password table */
#define PW_CHECK_FILE "@PREFIX/lib/krb5kdc/bad_passwd"

#define DEFAULT_ACL_DIR	"@PREFIX/lib/krb5kdc"

/*
 * krb5 slave support follows
 */

#define KPROP_DEFAULT_FILE "@PREFIX/lib/krb5kdc/slave_datatrans"
#define KPROPD_DEFAULT_FILE "@PREFIX/lib/krb5kdc/from_master"
#define KPROPD_DEFAULT_KDB5_EDIT "@PREFIX/admin/kdb5_edit"
#define KPROPD_DEFAULT_KRB_DB DEFAULT_KDB_FILE
#define KPROPD_ACL_FILE "@PREFIX/lib/krb5kdc/kpropd.acl"

#endif /* KRB5_OSCONF__ */
