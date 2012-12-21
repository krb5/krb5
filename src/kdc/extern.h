/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/extern.h */
/*
 * Copyright 1990,2001,2007,2009 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef __KRB5_KDC_EXTERN__
#define __KRB5_KDC_EXTERN__

typedef struct __kdc_realm_data {
    /*
     * General Kerberos per-realm data.
     */
    char *              realm_name;     /* Realm name                       */
/* XXX the real context should go away once the db_context is done.
 * The db_context is then associated with the realm keytab using
 * krb5_ktkdb_resolv(). There should be nothing in the context which
 * cannot span multiple realms -- proven */
    krb5_context        realm_context;  /* Context to be used for realm     */
    krb5_keytab         realm_keytab;   /* keytab to be used for this realm */
    char *              realm_profile;  /* Profile file for this realm      */
    char *              realm_host_based_services; /* do referral processing for these services
                                                    * If '*' - allow all referrals */
    char *              realm_no_host_referral; /* no referral for these services.
                                                 * If '*' - disallow all referrals and
                                                 * ignore realm_host_based_services */
    char *              realm_default_referral_realm; /* target realm for default referrals */
    krb5_boolean        realm_cross_realm_default_referral; /* do x-realm default referrals? */
    /*
     * Database per-realm data.
     */
    char *              realm_stash;    /* Stash file name for realm        */
    char *              realm_mpname;   /* Master principal name for realm  */
    krb5_principal      realm_mprinc;   /* Master principal for realm       */
    /*
     * Note realm_mkey is mkey read from stash or keyboard and may not be the
     * latest.  The mkey_list will have all the mkeys in use.
     */
    krb5_keyblock       realm_mkey;     /* Master key for this realm        */
    krb5_keylist_node * mkey_list;      /* list of mkeys in use for this realm */
    /*
     * TGS per-realm data.
     */
    krb5_principal      realm_tgsprinc; /* TGS principal for this realm     */
    /*
     * Other per-realm data.
     */
    char                *realm_ports;   /* Per-realm KDC UDP port */
    char                *realm_tcp_ports; /* Per-realm KDC TCP port */
    /*
     * Per-realm parameters.
     */
    krb5_deltat         realm_maxlife;  /* Maximum ticket life for realm    */
    krb5_deltat         realm_maxrlife; /* Maximum renewable life for realm */
    krb5_boolean        realm_reject_bad_transit; /* Accept unverifiable transited_realm ? */
    krb5_boolean        realm_restrict_anon;  /* Anon to local TGT only */
} kdc_realm_t;

extern kdc_realm_t      **kdc_realmlist;
extern int              kdc_numrealms;
extern kdc_realm_t      *kdc_active_realm;

kdc_realm_t *find_realm_data (char *, krb5_ui_4);

/*
 * Replace previously used global variables with the active (e.g. request's)
 * realm data.  This allows us to support multiple realms with minimal logic
 * changes.
 */
#define kdc_context                     kdc_active_realm->realm_context
#define max_life_for_realm              kdc_active_realm->realm_maxlife
#define max_renewable_life_for_realm    kdc_active_realm->realm_maxrlife
#define master_keyblock                 kdc_active_realm->realm_mkey
#define master_keylist                  kdc_active_realm->mkey_list
#define master_princ                    kdc_active_realm->realm_mprinc
#define tgs_server                      kdc_active_realm->realm_tgsprinc
#define reject_bad_transit              kdc_active_realm->realm_reject_bad_transit
#define restrict_anon                   kdc_active_realm->realm_restrict_anon
#define default_referral_realm          kdc_active_realm->realm_default_referral_realm
#define cross_realm_default_referral    kdc_active_realm->realm_cross_realm_default_referral

/* various externs for KDC */
extern krb5_data        empty_string;   /* an empty string */
extern krb5_timestamp   kdc_infinity;   /* greater than all other timestamps */
extern krb5_keyblock    psr_key;        /* key for predicted sam response */
extern const int        kdc_modifies_kdb;
extern krb5_int32       max_dgram_reply_size; /* maximum datagram size */

extern const int        vague_errors;
#endif /* __KRB5_KDC_EXTERN__ */
