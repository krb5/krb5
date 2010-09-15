/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/kdb/kdb_db2.h
 *
 * Copyright 1997 by the Massachusetts Institute of Technology.
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
 *
 * KDC Database backend definitions for Berkely DB.
 */
#ifndef KRB5_KDB_DB2_H
#define KRB5_KDB_DB2_H

#include "policy_db.h"

typedef struct _krb5_db2_context {
    krb5_boolean        db_inited;      /* Context initialized          */
    char *              db_name;        /* Name of database             */
    DB *                db;             /* DB handle                    */
    krb5_boolean        hashfirst;      /* Try hash database type first */
    char *              db_lf_name;     /* Name of lock file            */
    int                 db_lf_file;     /* File descriptor of lock file */
    time_t              db_lf_time;     /* Time last updated            */
    int                 db_locks_held;  /* Number of times locked       */
    int                 db_lock_mode;   /* Last lock mode, e.g. greatest*/
    krb5_boolean        db_nb_locks;    /* [Non]Blocking lock modes     */
    osa_adb_policy_t    policy_db;
    krb5_boolean        tempdb;
    krb5_boolean        disable_last_success;
    krb5_boolean        disable_lockout;
} krb5_db2_context;

#define KRB5_DB2_MAX_RETRY 5

#define KDB2_LOCK_EXT ".ok"
#define KDB2_TEMP_LOCK_EXT "~.ok"

krb5_error_code krb5_db2_init(krb5_context);
krb5_error_code krb5_db2_fini(krb5_context);
krb5_error_code krb5_db2_get_age(krb5_context, char *, time_t *);
krb5_error_code krb5_db2_rename(krb5_context, char *, char *, int );
krb5_error_code krb5_db2_get_principal(krb5_context, krb5_const_principal,
                                       unsigned int, krb5_db_entry **);
void krb5_db2_free_principal(krb5_context, krb5_db_entry *);
krb5_error_code krb5_db2_put_principal(krb5_context, krb5_db_entry *,
                                       char **db_args);
krb5_error_code krb5_db2_iterate_ext(krb5_context,
                                     krb5_error_code (*)(krb5_pointer,
                                                         krb5_db_entry *),
                                     krb5_pointer, int, int);
krb5_error_code krb5_db2_iterate(krb5_context, char *,
                                 krb5_error_code (*)(krb5_pointer,
                                                     krb5_db_entry *),
                                 krb5_pointer);
krb5_error_code krb5_db2_set_nonblocking(krb5_context, krb5_boolean,
                                         krb5_boolean *);
krb5_boolean krb5_db2_set_lockmode(krb5_context, krb5_boolean);
krb5_error_code krb5_db2_open_database(krb5_context);
krb5_error_code krb5_db2_close_database(krb5_context);

krb5_error_code
krb5_db2_delete_principal(krb5_context context,
                          krb5_const_principal searchfor);

krb5_error_code krb5_db2_lib_init(void);
krb5_error_code krb5_db2_lib_cleanup(void);
krb5_error_code krb5_db2_unlock(krb5_context);

krb5_error_code
krb5_db2_promote_db(krb5_context kcontext, char *conf_section, char **db_args);

krb5_error_code
krb5_db2_lock(krb5_context context, int in_mode);

krb5_error_code
krb5_db2_open(krb5_context kcontext, char *conf_section, char **db_args,
              int mode);

krb5_error_code krb5_db2_create(krb5_context kcontext, char *conf_section,
                                char **db_args);

krb5_error_code krb5_db2_destroy(krb5_context kcontext, char *conf_section,
                                 char **db_args);

const char *krb5_db2_err2str(krb5_context kcontext, long err_code);
void *krb5_db2_alloc(krb5_context kcontext, void *ptr, size_t size);
void krb5_db2_free(krb5_context kcontext, void *ptr);


/* policy management functions */
krb5_error_code
krb5_db2_create_policy(krb5_context context, osa_policy_ent_t entry);

krb5_error_code krb5_db2_get_policy(krb5_context kcontext,
                                    char *name, osa_policy_ent_t *policy);

krb5_error_code krb5_db2_put_policy(krb5_context kcontext,
                                    osa_policy_ent_t policy);

krb5_error_code krb5_db2_iter_policy(krb5_context kcontext, char *match_entry,
                                     osa_adb_iter_policy_func func,
                                     void *data);

krb5_error_code krb5_db2_delete_policy(krb5_context kcontext, char *policy);

void krb5_db2_free_policy(krb5_context kcontext, osa_policy_ent_t entry);

/* Thread-safety wrapper slapped on top of original implementation.  */
extern k5_mutex_t *krb5_db2_mutex;

/* lockout */
krb5_error_code
krb5_db2_lockout_check_policy(krb5_context context,
                              krb5_db_entry *entry,
                              krb5_timestamp stamp);

krb5_error_code
krb5_db2_lockout_audit(krb5_context context,
                       krb5_db_entry *entry,
                       krb5_timestamp stamp,
                       krb5_error_code status);

krb5_error_code
krb5_db2_check_policy_as(krb5_context kcontext, krb5_kdc_req *request,
                         krb5_db_entry *client, krb5_db_entry *server,
                         krb5_timestamp kdc_time, const char **status,
                         krb5_data *e_data);

void
krb5_db2_audit_as_req(krb5_context kcontext, krb5_kdc_req *request,
                      krb5_db_entry *client, krb5_db_entry *server,
                      krb5_timestamp authtime, krb5_error_code error_code);

#endif /* KRB5_KDB_DB2_H */
