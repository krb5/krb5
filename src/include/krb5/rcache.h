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

#ifndef __KRB5_RCACHE__
#define __KRB5_RCACHE__
typedef struct krb5_rc_st {
	struct krb5_rc_ops *ops;
	void *data;
} *krb5_rcache;

struct krb5_rc_ops {
	char *prefix;
	int (*resolve) PROTOTYPE((krb5_rcache *id, char *residual));
	int (*new) PROTOTYPE((krb5_rcache *id, krb5_rc_ops *));
	char *(*get_name) PROTOTYPE((krb5_rcache));
	int (*init) PROTOTYPE((krb5_rcache, krb5_timestamp));
	int (*recover) (krb5_rcache));
	int (*destroy) PROTOTYPE((krb5_rcache));
	int (*close) PROTOTYPE((krb5_rcache));
	int (*store) PROTOTYPE((krb5_rcache, krb5_tkt_authent *,
				krb_boolean expunge));
	int (*search) PROTOTYPE((krb5_rcache, krb5_tkt_authent *));
	int (*get_span) PROTOTYPE((krb5_rcache));
	int (*remove_cred) PROTOTYPE((krb5_rcache, krb5_tkt_authent *));
	int (*expunge) PROTOTYPE((krb_acache));
};


#endif /* __KRB5_RCACHE__ */
