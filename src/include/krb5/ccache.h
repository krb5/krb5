/*
 * include/krb5/ccache.h
 *
 * Copyright 1989,1991 by the Massachusetts Institute of Technology.
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
 * Credentials cache definitions.
 */


#ifndef KRB5_CCACHE__
#define KRB5_CCACHE__

typedef	krb5_pointer	krb5_cc_cursor;	/* cursor for sequential lookup */

typedef struct _krb5_ccache {
    krb5_magic magic;
    struct _krb5_cc_ops FAR *ops;
    krb5_pointer data;
} FAR *krb5_ccache;

typedef struct _krb5_cc_ops {
    krb5_magic magic;
    char FAR *prefix;
    char FAR * (INTERFACE *get_name) NPROTOTYPE((krb5_context, krb5_ccache));
    krb5_error_code (INTERFACE *resolve) NPROTOTYPE((krb5_context, krb5_ccache FAR *,
					    char FAR *));
    krb5_error_code (INTERFACE *gen_new) NPROTOTYPE((krb5_context, krb5_ccache FAR *));
    krb5_error_code (INTERFACE *init) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_principal));
    krb5_error_code (INTERFACE *destroy) NPROTOTYPE((krb5_context, krb5_ccache));
    krb5_error_code (INTERFACE *close) NPROTOTYPE((krb5_context, krb5_ccache));
    krb5_error_code (INTERFACE *store) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_creds FAR *));
    krb5_error_code (INTERFACE *retrieve) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds FAR *,
					    krb5_creds FAR *));
    krb5_error_code (INTERFACE *get_princ) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_principal FAR *));
    krb5_error_code (INTERFACE *get_first) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_cc_cursor FAR *));
    krb5_error_code (INTERFACE *get_next) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_cc_cursor FAR *, krb5_creds FAR *));
    krb5_error_code (INTERFACE *end_get) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_cc_cursor FAR *));
    krb5_error_code (INTERFACE *remove_cred) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds FAR *));
    krb5_error_code (INTERFACE *set_flags) NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_flags));
} krb5_cc_ops;

/* for retrieve_cred */
#define	KRB5_TC_MATCH_TIMES		0x00000001
#define	KRB5_TC_MATCH_IS_SKEY		0x00000002
#define	KRB5_TC_MATCH_FLAGS		0x00000004
#define	KRB5_TC_MATCH_TIMES_EXACT	0x00000008
#define	KRB5_TC_MATCH_FLAGS_EXACT	0x00000010
#define	KRB5_TC_MATCH_AUTHDATA		0x00000020
#define	KRB5_TC_MATCH_SRV_NAMEONLY	0x00000040
#define	KRB5_TC_MATCH_2ND_TKT		0x00000080

/* for set_flags and other functions */
#define KRB5_TC_OPENCLOSE		0x00000001

#define krb5_cc_initialize(context, cache, principal) (*(cache)->ops->init)(context, cache, principal)
#define krb5_cc_gen_new(context, cache) (*(cache)->ops->gen_new)(context, cache)
#define krb5_cc_destroy(context, cache) (*(cache)->ops->destroy)(context, cache)
#define krb5_cc_close(context, cache) (*(cache)->ops->close)(context, cache)
#define krb5_cc_store_cred(context, cache, creds) (*(cache)->ops->store)(context, cache, creds)
#define krb5_cc_retrieve_cred(context, cache, flags, mcreds, creds) (*(cache)->ops->retrieve)(context, cache, flags, mcreds, creds)
#define krb5_cc_get_principal(context, cache, principal) (*(cache)->ops->get_princ)(context, cache, principal)
#define krb5_cc_start_seq_get(context, cache, cursor) (*(cache)->ops->get_first)(context, cache, cursor)
#define krb5_cc_next_cred(context, cache, cursor, creds) (*(cache)->ops->get_next)(context, cache, cursor, creds)
#define krb5_cc_end_seq_get(context, cache, cursor) (*(cache)->ops->end_get)(context, cache, cursor)
#define krb5_cc_remove_cred(context, cache, flags, creds) (*(cache)->ops->remove_cred)(context, cache,flags, creds)
#define krb5_cc_set_flags(context, cache, flags) (*(cache)->ops->set_flags)(context, cache, flags)
#define krb5_cc_get_name(context, cache) (*(cache)->ops->get_name)(context, cache)

extern krb5_cc_ops FAR *krb5_cc_dfl_ops;

#endif /* KRB5_CCACHE__ */
