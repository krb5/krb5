/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * allocations of extern stuff
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_extern_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>

/* real declarations of KDC's externs */
krb5_rcache kdc_rcache;

krb5_data empty_string = {0, ""};
krb5_timestamp infinity = KRB5_INT32_MAX; /* XXX */

krb5_deltat max_life_for_realm;		/* XXX parameter per-realm? */
krb5_deltat max_renewable_life_for_realm; /* XXX param per-realm? */

krb5_keyblock master_keyblock;
krb5_principal master_princ;

volatile int signal_requests_exit = 0;	/* gets set when signal hits */

char *dbm_db_name = DEFAULT_DBM_FILE;

