/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Replay detection cache definitions.
 */

#include <krb5/copyright.h>

#ifndef KRB5_RCACHE__
#define KRB5_RCACHE__

typedef struct krb5_rc_st {
    struct _krb5_rc_ops *ops;
    krb5_pointer data;
} *krb5_rcache;

typedef struct _krb5_rc_ops {
    char *type;
    krb5_error_code (*init)PROTOTYPE((krb5_rcache,krb5_deltat)); /* create */
    krb5_error_code (*recover)PROTOTYPE((krb5_rcache)); /* open */
    krb5_error_code (*destroy)PROTOTYPE((krb5_rcache));
    krb5_error_code (*close)PROTOTYPE((krb5_rcache));
    krb5_error_code (*store)PROTOTYPE((krb5_rcache,krb5_tkt_authent *));
    krb5_error_code (*expunge)PROTOTYPE((krb5_rcache));
    krb5_error_code (*get_span)PROTOTYPE((krb5_rcache,krb5_deltat *));
    char *(*get_name)PROTOTYPE((krb5_rcache));
    krb5_error_code (*resolve)PROTOTYPE((krb5_rcache, char *));
} krb5_rc_ops;

krb5_error_code krb5_rc_default PROTOTYPE((krb5_rcache *));
krb5_error_code krb5_rc_register_type PROTOTYPE((krb5_rc_ops *));
krb5_error_code krb5_rc_resolve_type PROTOTYPE((krb5_rcache *,char *));
krb5_error_code krb5_rc_resolve_full PROTOTYPE((krb5_rcache *,char *));
char *krb5_rc_get_type PROTOTYPE((krb5_rcache));
char *krb5_rc_default_type PROTOTYPE((void));
char *krb5_rc_default_name PROTOTYPE((void));

#define krb5_rc_initialize(id, span) (*(id)->ops->init)(id, span)
#define krb5_rc_recover(id) (*(id)->ops->recover)(id)
#define krb5_rc_destroy(id) (*(id)->ops->destroy)(id)
#define krb5_rc_close(id) (*(id)->ops->close)(id)
#define krb5_rc_store(id, authent) (*(id)->ops->store)(id, authent)
#define krb5_rc_expunge(id) (*(id)->ops->expunge)(id)
#define krb5_rc_get_lifespan(id, spanp) (*(id)->ops->get_span)(id, spanp)
#define krb5_rc_get_name(id) (*(id)->ops->get_name)(id)
#define krb5_rc_resolve(id, name) (*(id)->ops->resolve)(id, name)

extern krb5_rc_ops krb5_rc_dfl_ops;

#endif /* KRB5_RCACHE__ */
