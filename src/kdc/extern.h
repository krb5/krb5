/*
 * kdc/extern.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * <<< Description >>>
 */

#include <krb5/copyright.h>

#ifndef __KRB5_KDC_EXTERN__
#define __KRB5_KDC_EXTERN__

/* various externs for KDC */
extern krb5_rcache kdc_rcache;                /* KDC's replay cache */

extern krb5_data empty_string;		/* an empty string */
extern krb5_timestamp kdc_infinity;	/* greater than all other timestamps */

extern krb5_deltat max_life_for_realm;	/* XXX should be a parameter? */
extern krb5_deltat max_renewable_life_for_realm; /* XXX should be a parameter? */
extern krb5_encrypt_block master_encblock;

extern krb5_keyblock master_keyblock;
extern krb5_principal master_princ;

extern volatile int signal_requests_exit;
extern char *dbm_db_name;

extern krb5_keyblock tgs_key;
extern krb5_kvno tgs_kvno;
extern krb5_principal_data tgs_server_struct;
#define	tgs_server (&tgs_server_struct)

#endif /* __KRB5_KDC_EXTERN__ */
