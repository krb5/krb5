/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This header file contains information needed by internal routines
 * of the file-based ticket cache implementation.
 */


#ifndef KRB5_KTFILE__
#define KRB5_KTFILE__

#include <stdio.h>

/*
 * Constants
 */
#define IGNORE_VNO 0


/* 
 * Types
 */
typedef struct _krb5_ktfile_data {
    char *name;			/* Name of the file */
    FILE *openf;		/* open file, if any. */
} krb5_ktfile_data;

/*
 * Macros
 */
#define KTPRIVATE(id) ((krb5_ktfile_data *)(id)->data)
#define KTFILENAME(id) (((krb5_ktfile_data *)(id)->data)->name)
#define KTFILEP(id) (((krb5_ktfile_data *)(id)->data)->openf)

extern struct _krb5_kt_ops krb5_ktf_ops;
extern struct _krb5_kt_ops krb5_ktf_writable_ops;

/* widen prototypes, if needed */
#include <krb5/widen.h>

krb5_error_code krb5_ktfile_resolve PROTOTYPE((char *,
					       krb5_keytab *));
krb5_error_code krb5_ktfile_wresolve PROTOTYPE((char *,
					       krb5_keytab *));
krb5_error_code krb5_ktfile_get_name PROTOTYPE((krb5_keytab,
						char *,
						int));
krb5_error_code krb5_ktfile_close PROTOTYPE((krb5_keytab));
krb5_error_code krb5_ktfile_get_entry PROTOTYPE((krb5_keytab,
						 krb5_principal,
						 krb5_kvno,
						 krb5_keytab_entry *));
krb5_error_code krb5_ktfile_start_seq_get PROTOTYPE((krb5_keytab,
						     krb5_kt_cursor *));
krb5_error_code krb5_ktfile_get_next PROTOTYPE((krb5_keytab,
						krb5_keytab_entry *,
						krb5_kt_cursor *));
krb5_error_code krb5_ktfile_end_get PROTOTYPE((krb5_keytab,
					       krb5_kt_cursor *));
/* routines to be included on extended version (write routines) */
krb5_error_code krb5_ktfile_add PROTOTYPE((krb5_keytab,
					   krb5_keytab_entry *));
krb5_error_code krb5_ktfile_remove PROTOTYPE((krb5_keytab,
					      krb5_keytab_entry *));

krb5_error_code krb5_ktfileint_openr PROTOTYPE((krb5_keytab));
krb5_error_code krb5_ktfileint_openw PROTOTYPE((krb5_keytab));
krb5_error_code krb5_ktfileint_close PROTOTYPE((krb5_keytab));
krb5_error_code krb5_ktfileint_read_entry PROTOTYPE((krb5_keytab,
						     krb5_keytab_entry **));
krb5_error_code krb5_ktfileint_write_entry PROTOTYPE((krb5_keytab,
						      krb5_keytab_entry *));
/* and back to normal... */
#include <krb5/narrow.h>

#endif /* KRB5_KTFILE__ */
