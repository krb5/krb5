#ifndef KRB5_KDB_HDB_H
#define KRB5_KDB_HDB_H

#include "k5-plugin.h"
#include "hdb.h"

typedef struct _kh_db_context {
    k5_mutex_t *lock;
    heim_context hcontext;
    HDB *hdb;

    struct plugin_file_handle *libkrb5;
    krb5_error_code (*heim_init_context)(heim_context *);
    void (*heim_free_context)(heim_context);
    void (*heim_free_principal)(heim_context, Principal *);

    struct plugin_file_handle *libhdb;
    krb5_error_code (*hdb_create)(heim_context, HDB **, const char *);
    void (*hdb_free_entry)(heim_context, hdb_entry_ex *);
} kh_db_context;

#endif /* KRB5_KDB_HDB_H */

