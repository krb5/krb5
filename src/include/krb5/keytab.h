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
 * Keytab definitions.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_KEYTAB__
#define __KRB5_KEYTAB__


typedef krb5_pointer krb5_kt_cursor;	/* XXX */

typedef struct krb5_keytab_entry_st {
    krb5_principal principal;	/* principal of this key */
    krb5_keyblock *key;		/* the secret key */
    krb5_kvno vno;		/* key version number */
} krb5_keytab_entry;


typedef struct krb5_kt_st {
	struct krb5_kt_ops *ops;
	krb5_pointer data;
} *krb5_keytab;


typedef struct _krb5_kt_ops {
	char *prefix;
        /* routines always present */
	int (*resolve) PROTOTYPE((char *,
				  krb5_keytab));
	int (*get_name) PROTOTYPE((krb5_ccache,
				   char *,
				   int));
	int (*close) PROTOTYPE((krb5_keytab *));
	int (*get) PROTOTYPE((krb5_keytab,
			      krb5_principal,
			      krb5_kvno,
			      krb5_keytab_entry *));
	int (*start_seq_get) PROTOTYPE((krb5_keytab,
					krb5_kt_cursor *));	
	int (*get_next) PROTOTYPE((krb5_keytab,
				   krb5_keytab_entry *,
				   krb5_kt_cursor));
	int (*end_get) PROTOTYPE((krb5_keytab,
				  krb5_kt_cursor));
	/* routines to be included on extended version (write routines) */
	int (*add) PROTOTYPE((krb5_keytab,
			      krb5_keytab_entry *));
	int (*remove) PROTOTYPE((krb5_keytab,
				  krb5_kt_cursor));
} krb5_kt_ops;

#endif /* __KRB5_KEYTAB__ */
