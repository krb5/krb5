/*
 * This prototype for k5-int.h (Krb5 internals include file)
 * includes the user-visible definitions from krb5.h and then
 * includes other definitions that are not user-visible but are
 * required for compiling Kerberos internal routines.
 *
 * John Gilmore, Cygnus Support, Sat Jan 21 22:45:52 PST 1995
 */

#ifndef _KRB5_INT_H
#define _KRB5_INT_H

#include "k5-config.h"

#include "krb5.h"

#ifdef NEED_SOCKETS
#include "k5-sockets.h"
#endif

/* krb5/krb5.h includes many other .h files in the krb5 subdirectory.
   The ones that it doesn't include, we include below.  */

#include "k5-errors.h"

#include "asn1.h"
#include "copyright.h"
#include "dbm.h"
#include "ext-proto.h"
/* Needed to define time_t for kdb.h prototypes.  */
#include "sysincl.h"
#include "los-proto.h"
#include "kdb.h"
#include "kdb_dbm.h"
#include "libos.h"
#include "mit-des.h"
#include "preauth.h"
#include "rsa-md5.h"
/* #include "krb5/wordsize.h" -- comes in through base-defs.h. */
#if !defined(_MACINTOSH)
#include "profile.h"
#else
typedef unsigned long profile_t;
#endif

struct _krb5_context {
	krb5_magic	magic;
	krb5_enctype  FAR *etypes;
	int		etype_count;
	void	      FAR *os_context;
	char	      FAR *default_realm;
	profile_t     profile;
	void	      FAR *db_context;
};
#endif /* _KRB5_INT_H */
