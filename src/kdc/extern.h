/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * <<< Description >>>
 */

#include <krb5/copyright.h>

#ifndef __KRB5_KDC_EXTERN__
#define __KRB5_KDC_EXTERN__

/* various externs for KDC */
extern krb5_rcache kdc_rcache;		/* KDC's replay cache */

extern krb5_data empty_string;		/* an empty string */
extern krb5_timestamp infinity;		/* greater than all other timestamps */

extern krb5_deltat max_life_for_realm;	/* XXX should be a parameter? */
extern krb5_deltat max_renewable_life_for_realm; /* XXX should be a parameter? */
extern krb5_encrypt_block master_encblock;

extern krb5_keyblock master_keyblock;
extern krb5_principal master_princ;

extern volatile int signal_requests_exit;
extern char *dbm_db_name;

#endif /* __KRB5_KDC_EXTERN__ */
