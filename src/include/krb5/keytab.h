/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Keytab definitions.
 */

#include <krb5/copyright.h>

#ifndef KRB5_KEYTAB__
#define KRB5_KEYTAB__


/* XXX */
#define MAX_KEYTAB_NAME_LEN 1100 /* Long enough for MAXPATHLEN + some extra */

typedef krb5_pointer krb5_kt_cursor;	/* XXX */

typedef struct krb5_keytab_entry_st {
    krb5_principal principal;	/* principal of this key */
    krb5_kvno vno;		/* key version number */
    krb5_keyblock key;		/* the secret key */
} krb5_keytab_entry;


typedef struct _krb5_kt {
	struct _krb5_kt_ops *ops;
	krb5_pointer data;
} *krb5_keytab;


typedef struct _krb5_kt_ops {
	char *prefix;
        /* routines always present */
	krb5_error_code (*resolve) PROTOTYPE((char *,
					      krb5_keytab *));
	krb5_error_code (*get_name) PROTOTYPE((krb5_keytab,
					       char *,
					       int));
	krb5_error_code (*close) PROTOTYPE((krb5_keytab));
	krb5_error_code (*get) PROTOTYPE((krb5_keytab,
					  krb5_principal,
					  krb5_kvno,
					  krb5_keytab_entry *));
	krb5_error_code (*start_seq_get) PROTOTYPE((krb5_keytab,
						    krb5_kt_cursor *));	
	krb5_error_code (*get_next) PROTOTYPE((krb5_keytab,
					       krb5_keytab_entry *,
					       krb5_kt_cursor));
	krb5_error_code (*end_get) PROTOTYPE((krb5_keytab,
					      krb5_kt_cursor));
	/* routines to be included on extended version (write routines) */
	krb5_error_code (*add) PROTOTYPE((krb5_keytab,
					  krb5_keytab_entry *));
	krb5_error_code (*remove) PROTOTYPE((krb5_keytab,
					     krb5_keytab_entry *));
} krb5_kt_ops;
#define krb5_kt_get_name(keytab, name, namelen) (*(keytab)->ops->get_name)(keytab,name,namelen)
#define krb5_kt_close(keytab) (*(keytab)->ops->close)(keytab)
#define krb5_kt_get_entry(keytab, principal, vno, entry) (*(keytab)->ops->get)(keytab, principal, vno, entry)
#define krb5_kt_start_seq_get(keytab, cursor) (*(keytab)->ops->start_seq_get)(keytab, cursor)
#define krb5_kt_next_entry(keytab, entry, cursor) (*(keytab)->ops->get_next)(keytab, entry, cursor)
#define krb5_kt_end_seq_get(keytab, cursor) (*(keytab)->ops->end_get)(keytab, cursor)
/* remove and add are functions, so that they can return NOWRITE
   if not a writable keytab */


extern krb5_kt_ops krb5_kt_dfl_ops;

#endif /* KRB5_KEYTAB__ */
