/*
 * lib/krb5/keytab/srvtab/ktsrvtab.h
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This header file contains information needed by internal routines
 * of the file-based ticket cache implementation.
 */


#ifndef KRB5_KTSRVTAB__
#define KRB5_KTSRVTAB__

#include <stdio.h>

/*
 * Constants
 */
#define IGNORE_VNO 0
#define IGNORE_ENCTYPE 0

#define KRB5_KT_VNO_1	0x0501	/* krb v5, keytab version 1 (DCE compat) */
#define KRB5_KT_VNO	0x0502	/* krb v5, keytab version 2 (standard)  */

#define KRB5_KT_DEFAULT_VNO KRB5_KT_VNO

/* 
 * Types
 */
typedef struct _krb5_ktsrvtab_data {
    char *name;			/* Name of the file */
    FILE *openf;		/* open file, if any. */
} krb5_ktsrvtab_data;

/*
 * Macros
 */
#define KTPRIVATE(id) ((krb5_ktsrvtab_data *)(id)->data)
#define KTFILENAME(id) (((krb5_ktsrvtab_data *)(id)->data)->name)
#define KTFILEP(id) (((krb5_ktsrvtab_data *)(id)->data)->openf)

extern struct _krb5_kt_ops krb5_kts_ops;

krb5_error_code KRB5_CALLCONV krb5_ktsrvtab_resolve
	PROTOTYPE((krb5_context,
		   const char *,
		   krb5_keytab *));

krb5_error_code KRB5_CALLCONV krb5_ktsrvtab_get_name
	PROTOTYPE((krb5_context,
		   krb5_keytab,
		   char *,
		   int));

krb5_error_code KRB5_CALLCONV krb5_ktsrvtab_close
	PROTOTYPE((krb5_context,
		   krb5_keytab));

krb5_error_code KRB5_CALLCONV krb5_ktsrvtab_get_entry
	PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_const_principal,
		   krb5_kvno,
		   krb5_enctype,
		   krb5_keytab_entry *));

krb5_error_code KRB5_CALLCONV krb5_ktsrvtab_start_seq_get
	PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_kt_cursor *));

krb5_error_code KRB5_CALLCONV krb5_ktsrvtab_get_next
	PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *,
		   krb5_kt_cursor *));

krb5_error_code KRB5_CALLCONV krb5_ktsrvtab_end_get
	PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_kt_cursor *));

krb5_error_code krb5_ktsrvint_open
	PROTOTYPE((krb5_context,
		   krb5_keytab));

krb5_error_code krb5_ktsrvint_close
	PROTOTYPE((krb5_context,
		   krb5_keytab));

krb5_error_code krb5_ktsrvint_read_entry 
	PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *));

#endif /* KRB5_KTSRVTAB__ */
