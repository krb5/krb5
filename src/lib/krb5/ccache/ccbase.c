/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Registration functions for ccache.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ccbase_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

extern krb5_cc_ops *krb5_cc_dfl_ops;
struct krb5_cc_typelist
 {
  krb5_cc_ops *ops;
  struct krb5_cc_typelist *next;
 };
static struct krb5_cc_typelist *cc_typehead = 0;

/*
 * Register a new credentials cache type
 * If override is set, replace any existing ccache with that type tag
 */

krb5_error_code
krb5_cc_register(DECLARG(krb5_cc_ops *,ops),
		 DECLARG(krb5_boolean,override))
OLDDECLARG(krb5_cc_ops *,ops)
OLDDECLARG(krb5_boolean,override)
{
    struct krb5_cc_typelist *t;
    for (t = cc_typehead;t && strcmp(t->ops->prefix,ops->prefix);t = t->next)
	;
    if (t) {
	if (override) {
	    t->ops = ops;
	    return 0;
	} else
	    return KRB5_CC_TYPE_EXISTS;
    }
    if (!(t = (struct krb5_cc_typelist *) malloc(sizeof(*t))))
	return ENOMEM;			/* XXX */
    t->next = cc_typehead;
    t->ops = ops;
    cc_typehead = t;
    return 0;
}

/*
 * Resolve a credential cache name into a cred. cache object.
 *
 * The name is currently constrained to be of the form "type:residual";
 *
 * The "type" portion corresponds to one of the predefined credential
 * cache types, while the "residual" portion is specific to the
 * particular cache type.
 */

krb5_error_code krb5_cc_resolve (name, cache)
    char *name;
    krb5_ccache *cache;
{
    struct krb5_cc_typelist *tlist;
    char *pfx, *resid, *cp;
    int pfxlen;
    
    cp = strchr (name, ':');
    if (!cp)
	return KRB5_CC_BADNAME;

    pfxlen = cp - name;
    resid = name + pfxlen + 1;
	
    pfx = malloc (pfxlen+1);
    if (!pfx)
	return ENOMEM;

    memcpy (pfx, name, pfxlen);
    pfx[pfxlen] = '\0';

    *cache = (krb5_ccache) 0;

    for (tlist = cc_typehead; tlist; tlist = tlist->next) {
	if (strcmp (tlist->ops->prefix, pfx) == 0) {
	    free(pfx);
	    return (*tlist->ops->resolve)(cache, resid);
	}
    }
    if (krb5_cc_dfl_ops && !strcmp (pfx, krb5_cc_dfl_ops->prefix)) {
	free (pfx);
	return (*krb5_cc_dfl_ops->resolve)(cache, resid);
    }
    free(pfx);
    return KRB5_CC_UNKNOWN_TYPE;
}
