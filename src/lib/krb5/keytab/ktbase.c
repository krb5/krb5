/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Registration functions for keytab.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktbase_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

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
krb5_kt_register(ops)
krb5_kt_ops *ops;
{
    struct krb5_kt_typelist *t;
    for (t = kt_typehead;t && strcmp(t->ops->prefix,ops->prefix);t = t->next)
	;
    if (t) {
	return KRB5_KT_TYPE_EXISTS;
    }
    if (!(t = (struct krb5_kt_typelist *) malloc(sizeof(*t))))
	return ENOMEM;			/* XXX */
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

krb5_error_code krb5_kt_resolve (name, ktid)
    const char *name;
    krb5_keytab *ktid;
{
    struct krb5_kt_typelist *tlist;
    char *pfx, *resid, *cp;
    int pfxlen;
    
    cp = strchr (name, ':');
    if (!cp)
	return KRB5_KT_BADNAME;

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
	    return (*tlist->ops->resolve)(resid, ktid);
	}
    }
    free(pfx);
    return KRB5_KT_UNKNOWN_TYPE;
}
