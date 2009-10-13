#ifndef KRB5_KDB_HDB_H
#define KRB5_KDB_HDB_H

#include "k5-plugin.h"
#include "hdb.h"
#include "windc_plugin.h"

typedef struct _kh_db_context {
    k5_mutex_t *lock;
    heim_context hcontext;
    HDB *hdb;

    /* libkrb5 APIs */
    struct plugin_file_handle *libkrb5;
    krb5_error_code (*heim_init_context)(heim_context *);
    void (*heim_free_context)(heim_context);
    void (*heim_free_principal)(heim_context, Principal *);
    void (*heim_pac_free)(heim_context, heim_pac);
    krb5_error_code (*heim_pac_parse)(heim_context, const void *,
                                      size_t, heim_pac *);
    krb5_error_code (*heim_pac_verify)(heim_context, const heim_pac,
                                       time_t, const Principal *,
                                       const EncryptionKey *,
                                       const EncryptionKey *);
    krb5_error_code (*heim_pac_sign)(heim_context, heim_pac,
                                     time_t, Principal *,
                                     const EncryptionKey *,
                                     const EncryptionKey *,
                                     heim_octet_string *);

    /* libhdb APIs */
    struct plugin_file_handle *libhdb;
    krb5_error_code (*hdb_create)(heim_context, HDB **, const char *);
    void (*hdb_free_entry)(heim_context, hdb_entry_ex *);

    /* widdc SPIs */
    struct plugin_dir_handle windc_plugins;
    krb5plugin_windc_ftable *windc;
    void *windc_ctx;
} kh_db_context;

#define KH_DB_CONTEXT(_context)    \
    ((kh_db_context *)(_context)->dal_handle->db_context)

#define KH_DB_ENTRY(_entry)         \
    ((hdb_entry_ex *)(_entry)->e_data)

krb5_error_code
kh_db_sign_auth_data(krb5_context context,
                     unsigned int method,
                     const krb5_data *req_data,
                     krb5_data *rep_data);

krb5_error_code
kh_map_error(krb5_error_code code);

krb5_error_code
kh_marshal_Principal(krb5_context context,
                     krb5_const_principal kprinc,
                     Principal **out_hprinc);

void
kh_free_Principal(krb5_context context,
                  Principal *principal);

#endif /* KRB5_KDB_HDB_H */

