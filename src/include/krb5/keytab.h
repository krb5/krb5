/*
 * include/krb5/keytab.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * Keytab definitions.
 */


#ifndef KRB5_KEYTAB__
#define KRB5_KEYTAB__


/* XXX */
#define MAX_KEYTAB_NAME_LEN 1100 /* Long enough for MAXPATHLEN + some extra */

typedef krb5_pointer krb5_kt_cursor;	/* XXX */

typedef struct krb5_keytab_entry_st {
    krb5_principal principal;	/* principal of this key */
    krb5_timestamp timestamp;   /* time entry written to keytable */
    krb5_kvno vno;		/* key version number */
    krb5_keyblock key;		/* the secret key */
} krb5_keytab_entry;


typedef struct _krb5_kt {
	struct _krb5_kt_ops *ops;
	krb5_pointer data;
} *krb5_keytab;


/* widen prototypes, if needed */
#include <krb5/widen.h>

typedef struct _krb5_kt_ops {
	char *prefix;
        /* routines always present */
	krb5_error_code (*resolve) NPROTOTYPE((char *,
					      krb5_keytab *));
	krb5_error_code (*get_name) NPROTOTYPE((krb5_keytab,
					       char *,
					       int));
	krb5_error_code (*close) NPROTOTYPE((krb5_keytab));
	krb5_error_code (*get) NPROTOTYPE((krb5_keytab,
					  krb5_principal,
					  krb5_kvno,
					  krb5_keytab_entry *));
	krb5_error_code (*start_seq_get) NPROTOTYPE((krb5_keytab,
						    krb5_kt_cursor *));	
	krb5_error_code (*get_next) NPROTOTYPE((krb5_keytab,
					       krb5_keytab_entry *,
					       krb5_kt_cursor *));
	krb5_error_code (*end_get) NPROTOTYPE((krb5_keytab,
					      krb5_kt_cursor *));
	/* routines to be included on extended version (write routines) */
	krb5_error_code (*add) NPROTOTYPE((krb5_keytab,
					  krb5_keytab_entry *));
	krb5_error_code (*remove) NPROTOTYPE((krb5_keytab,
					     krb5_keytab_entry *));
} krb5_kt_ops;

/* and back to narrow */
#include <krb5/narrow.h>

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
