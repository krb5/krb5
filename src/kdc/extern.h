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

#ifndef __KRB5_KDC_EXTERN__
#define __KRB5_KDC_EXTERN__

typedef struct __kdc_realm_data {
    /*
     * General Kerberos per-realm data.
     */
    char *		realm_name;	/* Realm name			    */
/* XXX the real context should go away once the db_context is done. 
 * The db_context is then associated with the realm keytab using 
 * krb5_ktkdb_resolv(). There should be nothing in the context which 
 * cannot span multiple realms -- proven */
    krb5_context	realm_context;	/* Context to be used for realm	    */
    krb5_keytab		realm_keytab; 	/* keytab to be used for this realm */
    char *		realm_profile;	/* Profile file for this realm	    */
    /*
     * Database per-realm data.
     */
    char *		realm_dbname;	/* Database name for realm	    */
    char *		realm_stash;	/* Stash file name for realm	    */
    char *		realm_mpname;	/* Master principal name for realm  */
    krb5_principal	realm_mprinc;	/* Master principal for realm	    */
    krb5_keyblock	realm_mkey;	/* Master key for this realm	    */
    krb5_kvno		realm_mkvno;	/* Master key vno for this realm    */
    /*
     * TGS per-realm data.
     */
    krb5_principal	realm_tgsprinc;	/* TGS principal for this realm	    */
    krb5_keyblock	realm_tgskey;	/* TGS' key for this realm	    */
    krb5_kvno		realm_tgskvno;	/* TGS' key vno for this realm	    */
    /*
     * Other per-realm data.
     */
    krb5_encrypt_block	realm_encblock;	/* Per-realm master encryption block*/
    char		*realm_ports;	/* Per-realm KDC port */
    /*
     * Per-realm parameters.
     */
    krb5_deltat		realm_maxlife;	/* Maximum ticket life for realm    */
    krb5_deltat		realm_maxrlife;	/* Maximum renewable life for realm */
    void		*realm_kstypes;	/* Key/Salts supported for realm    */
    krb5_int32		realm_nkstypes;	/* Number of key/salts		    */
} kdc_realm_t;

extern kdc_realm_t	**kdc_realmlist;
extern int		kdc_numrealms;
extern kdc_realm_t	*kdc_active_realm;

/*
 * Replace previously used global variables with the active (e.g. request's)
 * realm data.  This allows us to support multiple realms with minimal logic
 * changes.
 */
#define	kdc_context			kdc_active_realm->realm_context
#define	max_life_for_realm		kdc_active_realm->realm_maxlife
#define	max_renewable_life_for_realm	kdc_active_realm->realm_maxrlife
#define	master_encblock			kdc_active_realm->realm_encblock
#define	master_keyblock			kdc_active_realm->realm_mkey
#define	master_princ			kdc_active_realm->realm_mprinc
#define	tgs_key				kdc_active_realm->realm_tgskey
#define	tgs_kvno			kdc_active_realm->realm_tgskvno
#define	tgs_server_struct		*(kdc_active_realm->realm_tgsprinc)
#define	tgs_server			kdc_active_realm->realm_tgsprinc
#define	dbm_db_name			kdc_active_realm->realm_dbname
#define	primary_port			kdc_active_realm->realm_pport

/* various externs for KDC */
extern krb5_data 	empty_string;	/* an empty string */
extern krb5_timestamp 	kdc_infinity;	/* greater than all other timestamps */
extern krb5_rcache	kdc_rcache;	/* replay cache */

extern volatile int signal_requests_exit;
#endif /* __KRB5_KDC_EXTERN__ */
