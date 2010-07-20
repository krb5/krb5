/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugins/kdb/hdb/kdb_hdb.c
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

#ifndef KRB5_KDB_HDB_H
#define KRB5_KDB_HDB_H

#include "k5-plugin.h"
#include "hdb.h"
#include "windc_plugin.h"

typedef krb5_int32 heim_error_code;

typedef struct _kh_db_context {
    k5_mutex_t *lock;
    heim_context hcontext;
    HDB *hdb;
    int mode;

    /* libkrb5 APIs */
    struct plugin_file_handle *libkrb5;
    heim_error_code (*heim_init_context)(heim_context *);
    void (*heim_free_context)(heim_context);
    void (*heim_free_principal)(heim_context, Principal *);
    heim_error_code (*heim_free_addresses)(heim_context, HostAddresses *);
    void (*heim_pac_free)(heim_context, heim_pac);
    heim_error_code (*heim_pac_parse)(heim_context, const void *,
                                      size_t, heim_pac *);
    heim_error_code (*heim_pac_verify)(heim_context, const heim_pac,
                                       time_t, const Principal *,
                                       const EncryptionKey *,
                                       const EncryptionKey *);
    heim_error_code (*heim_pac_sign)(heim_context, heim_pac,
                                     time_t, Principal *,
                                     const EncryptionKey *,
                                     const EncryptionKey *,
                                     heim_octet_string *);

    /* libhdb APIs */
    struct plugin_file_handle *libhdb;
    heim_error_code (*hdb_create)(heim_context, HDB **, const char *);
    heim_error_code (*hdb_seal_key)(heim_context, HDB *, Key *);
    heim_error_code (*hdb_unseal_key)(heim_context, HDB *, Key *);
    heim_error_code (*hdb_set_master_key)(heim_context, HDB *, EncryptionKey *);
    void (*hdb_free_entry)(heim_context, hdb_entry_ex *);

    /* widdc SPIs */
    struct plugin_dir_handle windc_plugins;
    krb5plugin_windc_ftable *windc;
    void *windc_ctx;
} kh_db_context;

#define KH_DB_CONTEXT(_context)                                 \
    ((kh_db_context *)(_context)->dal_handle->db_context)

#define KH_DB_ENTRY(_entry)                     \
    ((hdb_entry_ex *)(_entry)->e_data)

/* kdb_hdb.c */

krb5_error_code
kh_map_error(heim_error_code code);

krb5_error_code
kh_get_principal(krb5_context context,
                 kh_db_context *kh,
                 krb5_const_principal princ,
                 unsigned int hflags,
                 krb5_db_entry **kentry);

void
kh_kdb_free_entry(krb5_context context,
                  kh_db_context *kh,
                  krb5_db_entry *entry);

krb5_error_code
kh_decrypt_key(krb5_context context,
               kh_db_context *kh,
               const krb5_key_data *key_data,
               krb5_keyblock *dbkey,
               krb5_keysalt *keysalt);

void
kh_hdb_free_entry(krb5_context context,
                  kh_db_context *kh,
                  hdb_entry_ex *entry);

/* kdb_marshal.c */

#define KH_MARSHAL_KEY(_kkey, _hkey)        do {                \
        (_hkey)->keytype            = (_kkey)->enctype;         \
        (_hkey)->keyvalue.data      = (_kkey)->contents;        \
        (_hkey)->keyvalue.length    = (_kkey)->length;          \
    } while (0)

krb5_error_code
kh_marshal_Principal(krb5_context context,
                     krb5_const_principal kprinc,
                     Principal **out_hprinc);

krb5_error_code
kh_unmarshal_Principal(krb5_context context,
                       const Principal *hprinc,
                       krb5_principal *out_kprinc);

void
kh_free_Principal(krb5_context context,
                  Principal *principal);

void
kh_free_Event(krb5_context context,
              Event *event);

void
kh_free_HostAddresses(krb5_context context,
                      HostAddresses *addrs);

krb5_error_code
kh_unmarshal_hdb_entry(krb5_context context,
                       const hdb_entry *hentry,
                       krb5_db_entry **kentry);

krb5_error_code
kh_marshal_hdb_entry(krb5_context context,
                     const krb5_db_entry *kentry,
                     hdb_entry *hentry);

/* kdb_windc.c */

krb5_error_code
kh_db_sign_auth_data(krb5_context kcontext,
                     unsigned int flags,
                     krb5_const_principal client_princ,
                     krb5_db_entry *client,
                     krb5_db_entry *server,
                     krb5_db_entry *krbtgt,
                     krb5_keyblock *client_key,
                     krb5_keyblock *server_key,
                     krb5_keyblock *krbtgt_key,
                     krb5_keyblock *session_key,
                     krb5_timestamp authtime,
                     krb5_authdata **tgt_auth_data,
                     krb5_authdata ***signed_auth_data);

krb5_error_code
kh_db_check_policy_as(krb5_context kcontext,
                      krb5_kdc_req *request,
                      krb5_db_entry *client,
                      krb5_db_entry *server,
                      krb5_timestamp kdc_time,
                      const char **status,
                      krb5_data *e_data);

krb5_error_code
kh_hdb_windc_init(krb5_context context,
                  const char *libdir,
                  kh_db_context *kh);

#endif /* KRB5_KDB_HDB_H */
