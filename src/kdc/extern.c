/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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

#include "extern.h"

/* real declarations of KDC's externs */
krb5_rcache kdc_rcache;

krb5_data empty_string = {0, ""};
krb5_timestamp kdc_infinity = KRB5_INT32_MAX; /* XXX */

krb5_deltat max_life_for_realm = KRB5_KDB_MAX_LIFE;		/* XXX parameter per-realm? */
krb5_deltat max_renewable_life_for_realm = KRB5_KDB_MAX_RLIFE; /* XXX param per-realm? */
krb5_encrypt_block master_encblock;

krb5_keyblock master_keyblock;
krb5_principal master_princ;

volatile int signal_requests_exit = 0;	/* gets set when signal hits */

char *dbm_db_name = DEFAULT_DBM_FILE;

krb5_keyblock tgs_key;
krb5_kvno tgs_kvno;

static krb5_data tgs_data[3] = { {sizeof(TGTNAME)-1, TGTNAME}, {0, 0}};
krb5_principal_data tgs_server_struct = { { 0, 0}, tgs_data, 2, 0};
