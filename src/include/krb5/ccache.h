/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Credentials cache definitions.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_CCACHE__
#define __KRB5_CCACHE__

typedef	krb5_pointer	krb5_cc_cursor;	/* cursor for sequential lookup */

typedef struct _krb5_ccache {
	struct krb5_cc_ops *ops;
	void *data;
} *krb5_ccache;

typedef struct _krb5_cc_ops {
	char *prefix;
	krb5_ccache (*resolve) PROTOTYPE((char *residual));
	krb5_ccache (*gen_new) PROTOTYPE((void));
	char *(*get_name) PROTOTYPE((krb5_ccache));
	int (*init) PROTOTYPE((krb5_ccache, krb5_principal));
	int (*destroy) PROTOTYPE((krb5_ccache));
	int (*close) PROTOTYPE((krb5_ccache));
	int (*store) PROTOTYPE((krb5_ccache, krb5_credentials *));
	int (*retrieve) PROTOTYPE((krb5_ccache, krb5_flags,
				   krb5_credentials *, krb5_credentials *));
	int (*get_princ) PROTOTYPE((krb5_ccache, krb5_principal *));
	int (*get_first) PROTOTYPE((krb5_ccache, krb5_cc_cursor *));
	int (*get_next) PROTOTYPE((krb5_ccache, krb5_cc_cursor *,
				   krb5_credentials *));
	int (*end_get) PROTOTYPE((krb5_ccache, krb5_cc_cursor *));
	int (*remove_cred) PROTOTYPE((krb5_ccache, krb5_flags,
				      krb5_credentials *));
	int (*set_flags) PROTOTYPE((krb5_ccache, krb5_cflags));
} krb5_cc_ops;

/* for retrieve_cred */
#define	KRB5_TC_MATCH_TIMES		0x00000001
#define	KRB5_TC_MATCH_IS_SKEY		0x00000002
#define	KRB5_TC_MATCH_FLAGS		0x00000004
#define	KRB5_TC_MATCH_TIMES_EXACT	0x00000008
#define	KRB5_TC_MATCH_FLAGS_EXACT	0x00000010

#endif /* __KRB5_CCACHE__ */
