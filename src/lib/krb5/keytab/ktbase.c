/*
 * lib/krb5/keytab/ktbase.c
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
 * Registration functions for keytab.
 */

#include "k5-int.h"

struct krb5_kt_typelist
 {
  krb5_kt_ops *ops;
  struct krb5_kt_typelist *next;
 };
static struct krb5_kt_typelist krb5_kt_typelist_dfl = { &krb5_kt_dfl_ops, 0 };
static struct krb5_kt_typelist *kt_typehead = &krb5_kt_typelist_dfl;

/*
 * Register a new key table type
 * don't replace if it already exists; return an error instead.
 */

krb5_error_code
krb5_kt_register(context, ops)
    krb5_context context;
    krb5_kt_ops *ops;
{
    struct krb5_kt_typelist *t;
    for (t = kt_typehead;t && strcmp(t->ops->prefix,ops->prefix);t = t->next)
	;
    if (t) {
	return KRB5_KT_TYPE_EXISTS;
    }
    if (!(t = (struct krb5_kt_typelist *) malloc(sizeof(*t))))
	return ENOMEM;
    t->next = kt_typehead;
    t->ops = ops;
    kt_typehead = t;
    return 0;
}

/*
 * Resolve a key table name into a keytab object.
 *
 * The name is currently constrained to be of the form "type:residual";
 *
 * The "type" portion corresponds to one of the registered key table
 * types, while the "residual" portion is specific to the
 * particular keytab type.
 */

krb5_error_code
krb5_kt_resolve (context, name, ktid)
    krb5_context context;
    const char *name;
    krb5_keytab *ktid;
{
    struct krb5_kt_typelist *tlist;
    char *pfx, *resid, *cp;
    int pfxlen;
    
    cp = strchr (name, ':');
    if (!cp) {
	    return (*krb5_kt_dfl_ops.resolve)(context, name, ktid);
    }

    pfxlen = cp - (char *)name;
    resid = (char *)name + pfxlen + 1;
	
    pfx = malloc (pfxlen+1);
    if (!pfx)
	return ENOMEM;

    memcpy (pfx, name, pfxlen);
    pfx[pfxlen] = '\0';

    *ktid = (krb5_keytab) 0;

    for (tlist = kt_typehead; tlist; tlist = tlist->next) {
	if (strcmp (tlist->ops->prefix, pfx) == 0) {
	    free(pfx);
	    return (*tlist->ops->resolve)(context, resid, ktid);
	}
    }
    free(pfx);
    return KRB5_KT_UNKNOWN_TYPE;
}
