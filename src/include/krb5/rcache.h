/*
 * include/krb5/rcache.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Replay detection cache definitions.
 */


#ifndef KRB5_RCACHE__
#define KRB5_RCACHE__

typedef struct krb5_rc_st {
    krb5_magic magic;
    struct _krb5_rc_ops FAR *ops;
    krb5_pointer data;
} FAR *krb5_rcache;

typedef struct _krb5_donot_replay {
    krb5_magic magic;
    char FAR *server;			/* null-terminated */
    char FAR *client;			/* null-terminated */
    krb5_int32 cusec;
    krb5_timestamp ctime;
} krb5_donot_replay;

typedef struct _krb5_rc_ops {
    krb5_magic magic;
    char FAR *type;
    krb5_error_code (*init)NPROTOTYPE((krb5_context, krb5_rcache,krb5_deltat)); /* create */
    krb5_error_code (*recover)NPROTOTYPE((krb5_context, krb5_rcache)); /* open */
    krb5_error_code (*destroy)NPROTOTYPE((krb5_context, krb5_rcache));
    krb5_error_code (*close)NPROTOTYPE((krb5_context, krb5_rcache));
    krb5_error_code (*store)NPROTOTYPE((krb5_context, krb5_rcache,krb5_donot_replay FAR *));
    krb5_error_code (*expunge)NPROTOTYPE((krb5_context, krb5_rcache));
    krb5_error_code (*get_span)NPROTOTYPE((krb5_context, krb5_rcache,krb5_deltat FAR *));
    char FAR *(*get_name)NPROTOTYPE((krb5_context, krb5_rcache));
    krb5_error_code (*resolve)NPROTOTYPE((krb5_context, krb5_rcache, char FAR *));
} krb5_rc_ops;

krb5_error_code krb5_rc_default 
	PROTOTYPE((krb5_context,
		   krb5_rcache FAR *));
krb5_error_code krb5_rc_register_type 
	PROTOTYPE((krb5_context,
		   krb5_rc_ops FAR *));
krb5_error_code krb5_rc_resolve_type 
	PROTOTYPE((krb5_context,
		   krb5_rcache FAR *,char FAR *));
krb5_error_code krb5_rc_resolve_full 
	PROTOTYPE((krb5_context,
		   krb5_rcache FAR *,char FAR *));
char FAR * krb5_rc_get_type 
	PROTOTYPE((krb5_context,
		   krb5_rcache));
char FAR * krb5_rc_default_type 
	PROTOTYPE((krb5_context));
char FAR * krb5_rc_default_name 
	PROTOTYPE((krb5_context));
krb5_error_code krb5_auth_to_rep 
	PROTOTYPE((krb5_context,
		   krb5_tkt_authent FAR *,
		   krb5_donot_replay FAR *));

#define krb5_rc_initialize(context, id, span) (*(id)->ops->init)(context, id, span)
#define krb5_rc_recover(context, id) (*(id)->ops->recover)(context, id)
#define krb5_rc_destroy(context, id) (*(id)->ops->destroy)(context, id)
#define krb5_rc_close(context, id) (*(id)->ops->close)(context, id)
#define krb5_rc_store(context, id, dontreplay) (*(id)->ops->store)(context, id, dontreplay)
#define krb5_rc_expunge(context, id) (*(id)->ops->expunge)(context, id)
#define krb5_rc_get_lifespan(context, id, spanp) (*(id)->ops->get_span)(context, id, spanp)
#define krb5_rc_get_name(context, id) (*(id)->ops->get_name)(context, id)
#define krb5_rc_resolve(context, id, name) (*(id)->ops->resolve)(context, id, name)

extern krb5_rc_ops krb5_rc_dfl_ops;

#endif /* KRB5_RCACHE__ */
