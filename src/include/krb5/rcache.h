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
	struct krb5_rc_ops *ops;
	void *data;
} *krb5_rcache;

typedef struct _krb5_rc_ops {
	char *prefix;
	krb5_error_code (*resolve) PROTOTYPE((krb5_rcache *,
					      char *));
	krb5_error_code (*new) PROTOTYPE((krb5_rcache *,
					  struct _krb5_rc_ops *));
	krb5_error_code (*get_name) PROTOTYPE((krb5_rcache, char *, int));
	krb5_error_code (*init) PROTOTYPE((krb5_rcache,
					   krb5_deltat));
	krb5_error_code (*recover) PROTOTYPE((krb5_rcache));
	krb5_error_code (*destroy) PROTOTYPE((krb5_rcache));
	krb5_error_code (*close) PROTOTYPE((krb5_rcache));
	krb5_error_code (*store) PROTOTYPE((krb5_rcache,
					    krb5_tkt_authent *,
					    krb5_boolean));
	krb5_error_code (*get_span) PROTOTYPE((krb5_rcache, krb5_deltat *));
	krb5_error_code (*expunge) PROTOTYPE((krb5_rcache));
} krb5_rc_ops;


#endif /* KRB5_RCACHE__ */
