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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Registration functions for keytab.
 */

#include "k5-int.h"

extern const krb5_kt_ops krb5_ktf_ops;
extern const krb5_kt_ops krb5_ktf_writable_ops;
extern const krb5_kt_ops krb5_kts_ops;

struct krb5_kt_typelist {
    const krb5_kt_ops *ops;
    struct krb5_kt_typelist *next;
};
static struct krb5_kt_typelist krb5_kt_typelist_wrfile  = {
    &krb5_ktf_writable_ops,
    0
};
static struct krb5_kt_typelist krb5_kt_typelist_file  = {
    &krb5_ktf_ops,
    &krb5_kt_typelist_wrfile
};
static struct krb5_kt_typelist krb5_kt_typelist_srvtab = {
    &krb5_kts_ops,
    &krb5_kt_typelist_file
};
static struct krb5_kt_typelist *kt_typehead = &krb5_kt_typelist_srvtab;


/*
 * Register a new key table type
 * don't replace if it already exists; return an error instead.
 */

krb5_error_code KRB5_CALLCONV
krb5_kt_register(krb5_context context, krb5_kt_ops *ops)
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

krb5_error_code KRB5_CALLCONV
krb5_kt_resolve (krb5_context context, const char *name, krb5_keytab *ktid)
{
    struct krb5_kt_typelist *tlist;
    char *pfx;
    unsigned int pfxlen;
    const char *cp, *resid;
    
    cp = strchr (name, ':');
    if (!cp) {
	    return (*krb5_kt_dfl_ops.resolve)(context, name, ktid);
    }

    pfxlen = cp - name;
    resid = name + pfxlen + 1;
	
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

/*
 * Routines to deal with externalizingt krb5_keytab.
 *	krb5_keytab_size();
 *	krb5_keytab_externalize();
 *	krb5_keytab_internalize();
 */
static krb5_error_code krb5_keytab_size
	(krb5_context, krb5_pointer, size_t *);
static krb5_error_code krb5_keytab_externalize
	(krb5_context, krb5_pointer, krb5_octet **, size_t *);
static krb5_error_code krb5_keytab_internalize
	(krb5_context,krb5_pointer *, krb5_octet **, size_t *);

/*
 * Serialization entry for this type.
 */
static const krb5_ser_entry krb5_keytab_ser_entry = {
    KV5M_KEYTAB,			/* Type			*/
    krb5_keytab_size,			/* Sizer routine	*/
    krb5_keytab_externalize,		/* Externalize routine	*/
    krb5_keytab_internalize		/* Internalize routine	*/
};

static krb5_error_code
krb5_keytab_size(krb5_context kcontext, krb5_pointer arg, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    krb5_ser_handle	shandle;

    kret = EINVAL;
    if ((keytab = (krb5_keytab) arg) &&
	keytab->ops &&
	(shandle = (krb5_ser_handle) keytab->ops->serializer) &&
	shandle->sizer)
	kret = (*shandle->sizer)(kcontext, arg, sizep);
    return(kret);
}

static krb5_error_code
krb5_keytab_externalize(krb5_context kcontext, krb5_pointer arg, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    krb5_ser_handle	shandle;

    kret = EINVAL;
    if ((keytab = (krb5_keytab) arg) &&
	keytab->ops &&
	(shandle = (krb5_ser_handle) keytab->ops->serializer) &&
	shandle->externalizer)
	kret = (*shandle->externalizer)(kcontext, arg, buffer, lenremain);
    return(kret);
}

static krb5_error_code
krb5_keytab_internalize(krb5_context kcontext, krb5_pointer *argp, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_ser_handle	shandle;

    kret = EINVAL;
    if ((shandle = (krb5_ser_handle) krb5_kt_dfl_ops.serializer) &&
	shandle->internalizer)
	kret = (*shandle->internalizer)(kcontext, argp, buffer, lenremain);
    return(kret);
}

krb5_error_code KRB5_CALLCONV
krb5_ser_keytab_init(krb5_context kcontext)
{
    return(krb5_register_serializer(kcontext, &krb5_keytab_ser_entry));
}
