/*
 * lib/krb5/ccache/ccbase.c
 *
 * Copyright 1990,2004,2008 by the Massachusetts Institute of Technology.
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
 * Registration functions for ccache.
 */

#include "k5-int.h"
#include "k5-thread.h"

#include "fcc.h"
#include "cc-int.h"

struct krb5_cc_typelist {
    const krb5_cc_ops *ops;
    struct krb5_cc_typelist *next;
};

struct krb5_cc_typecursor {
    struct krb5_cc_typelist *tptr;
};
/* typedef krb5_cc_typecursor in k5-int.h */

extern const krb5_cc_ops krb5_mcc_ops;

#define NEXT NULL

#ifdef _WIN32
extern const krb5_cc_ops krb5_lcc_ops;
static struct krb5_cc_typelist cc_lcc_entry = { &krb5_lcc_ops, NEXT };
#undef NEXT
#define NEXT &cc_lcc_entry
#endif

#ifdef USE_CCAPI_V3
extern const krb5_cc_ops krb5_cc_stdcc_ops;
static struct krb5_cc_typelist cc_stdcc_entry = { &krb5_cc_stdcc_ops, NEXT };
#undef NEXT
#define NEXT &cc_stdcc_entry
#endif

static struct krb5_cc_typelist cc_mcc_entry = { &krb5_mcc_ops, NEXT };
#undef NEXT
#define NEXT &cc_mcc_entry

#ifndef NO_FILE_CCACHE
static struct krb5_cc_typelist cc_fcc_entry = { &krb5_cc_file_ops, NEXT };
#undef NEXT
#define NEXT &cc_fcc_entry
#endif

#ifdef USE_KEYRING_CCACHE
extern const krb5_cc_ops krb5_krcc_ops;
static struct krb5_cc_typelist cc_krcc_entry = { &krb5_krcc_ops, NEXT };
#undef NEXT
#define NEXT &cc_krcc_entry
#endif /* USE_KEYRING_CCACHE */


#define INITIAL_TYPEHEAD (NEXT)
static struct krb5_cc_typelist *cc_typehead = INITIAL_TYPEHEAD;
static k5_mutex_t cc_typelist_lock = K5_MUTEX_PARTIAL_INITIALIZER;

/* mutex for krb5_cccol_[un]lock */
static k5_cc_mutex cccol_lock = K5_CC_MUTEX_PARTIAL_INITIALIZER;

static krb5_error_code
krb5int_cc_getops(krb5_context, const char *, const krb5_cc_ops **);

int
krb5int_cc_initialize(void)
{
    int err;

    err = k5_cc_mutex_finish_init(&cccol_lock);
    if (err)
	return err;
    err = k5_cc_mutex_finish_init(&krb5int_mcc_mutex);
    if (err)
	return err;
    err = k5_mutex_finish_init(&cc_typelist_lock);
    if (err)
	return err;
#ifndef NO_FILE_CCACHE
    err = k5_cc_mutex_finish_init(&krb5int_cc_file_mutex);
    if (err)
	return err;
#endif
#ifdef USE_KEYRING_CCACHE
    err = k5_cc_mutex_finish_init(&krb5int_krcc_mutex);
    if (err)
	return err;
#endif
    return 0;
}

void
krb5int_cc_finalize(void)
{
    struct krb5_cc_typelist *t, *t_next;
    k5_cccol_force_unlock();
    k5_cc_mutex_destroy(&cccol_lock);
    k5_mutex_destroy(&cc_typelist_lock);
#ifndef NO_FILE_CCACHE
    k5_cc_mutex_destroy(&krb5int_cc_file_mutex);
#endif
    k5_cc_mutex_destroy(&krb5int_mcc_mutex);
#ifdef USE_KEYRING_CCACHE
    k5_cc_mutex_destroy(&krb5int_krcc_mutex);
#endif
    for (t = cc_typehead; t != INITIAL_TYPEHEAD; t = t_next) {
	t_next = t->next;
	free(t);
    }
}


/*
 * Register a new credentials cache type
 * If override is set, replace any existing ccache with that type tag
 */

krb5_error_code KRB5_CALLCONV
krb5_cc_register(krb5_context context, const krb5_cc_ops *ops, 
		 krb5_boolean override)
{
    struct krb5_cc_typelist *t;
    krb5_error_code err;

    err = k5_mutex_lock(&cc_typelist_lock);
    if (err)
	return err;
    for (t = cc_typehead;t && strcmp(t->ops->prefix,ops->prefix);t = t->next)
	;
    if (t) {
	if (override) {
	    t->ops = ops;
	    k5_mutex_unlock(&cc_typelist_lock);
	    return 0;
	} else {
	    k5_mutex_unlock(&cc_typelist_lock);
	    return KRB5_CC_TYPE_EXISTS;
	}
    }
    if (!(t = (struct krb5_cc_typelist *) malloc(sizeof(*t)))) {
	k5_mutex_unlock(&cc_typelist_lock);
	return ENOMEM;
    }
    t->next = cc_typehead;
    t->ops = ops;
    cc_typehead = t;
    k5_mutex_unlock(&cc_typelist_lock);
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

#include <ctype.h>
krb5_error_code KRB5_CALLCONV
krb5_cc_resolve (krb5_context context, const char *name, krb5_ccache *cache)
{
    char *pfx, *cp;
    const char *resid;
    unsigned int pfxlen;
    krb5_error_code err;
    const krb5_cc_ops *ops;

    if (name == NULL)
	return KRB5_CC_BADNAME;
    pfx = NULL;
    cp = strchr (name, ':');
    if (!cp) {
	if (krb5_cc_dfl_ops)
	    return (*krb5_cc_dfl_ops->resolve)(context, cache, name);
	else
	    return KRB5_CC_BADNAME;
    }

    pfxlen = cp - name;

    if ( pfxlen == 1 && isalpha((unsigned char) name[0]) ) {
        /* We found a drive letter not a prefix - use FILE */
        pfx = strdup("FILE");
        if (!pfx)
            return ENOMEM;

        resid = name;
    } else {
        resid = name + pfxlen + 1;

        pfx = malloc (pfxlen+1);
        if (!pfx)
            return ENOMEM;

        memcpy (pfx, name, pfxlen);
        pfx[pfxlen] = '\0';
    }

    *cache = (krb5_ccache) 0;

    err = krb5int_cc_getops(context, pfx, &ops);
    if (pfx != NULL)
	free(pfx);
    if (err)
	return err;

    return ops->resolve(context, cache, resid);
}

/*
 * cc_getops
 *
 * Internal function to return the ops vector for a given ccache
 * prefix string.
 */
static krb5_error_code
krb5int_cc_getops(
    krb5_context context,
    const char *pfx,
    const krb5_cc_ops **ops)
{
    krb5_error_code err;
    struct krb5_cc_typelist *tlist;

    err = k5_mutex_lock(&cc_typelist_lock);
    if (err)
	return err;

    for (tlist = cc_typehead; tlist; tlist = tlist->next) {
	if (strcmp (tlist->ops->prefix, pfx) == 0) {
	    *ops = tlist->ops;
	    k5_mutex_unlock(&cc_typelist_lock);
	    return 0;
	}
    }
    k5_mutex_unlock(&cc_typelist_lock);
    if (krb5_cc_dfl_ops && !strcmp (pfx, krb5_cc_dfl_ops->prefix)) {
	*ops = krb5_cc_dfl_ops;
	return 0;
    }
    return KRB5_CC_UNKNOWN_TYPE;
}

/*
 * cc_new_unique
 *
 * Generate a new unique ccache, given a ccache type and a hint
 * string.  Ignores the hint string for now.
 */
krb5_error_code KRB5_CALLCONV
krb5_cc_new_unique(
    krb5_context context,
    const char *type,
    const char *hint,
    krb5_ccache *id)
{
    const krb5_cc_ops *ops;
    krb5_error_code err;

    *id = NULL;

    err = krb5int_cc_getops(context, type, &ops);
    if (err)
	return err;

    return ops->gen_new(context, id);
}

/*
 * cc_typecursor
 *
 * Note: to avoid copying the typelist at cursor creation time, among
 * other things, we assume that the only additions ever occur to the
 * typelist.
 */
krb5_error_code
krb5int_cc_typecursor_new(krb5_context context, krb5_cc_typecursor *t)
{
    krb5_error_code err = 0;
    krb5_cc_typecursor n = NULL;

    *t = NULL;
    n = malloc(sizeof(*n));
    if (n == NULL)
	return ENOMEM;

    err = k5_mutex_lock(&cc_typelist_lock);
    if (err)
	goto errout;
    n->tptr = cc_typehead;
    err = k5_mutex_unlock(&cc_typelist_lock);
    if (err)
	goto errout;

    *t = n;
errout:
    if (err)
	free(n);
    return err;
}

krb5_error_code
krb5int_cc_typecursor_next(
    krb5_context context,
    krb5_cc_typecursor t,
    const krb5_cc_ops **ops)
{
    krb5_error_code err = 0;

    *ops = NULL;
    if (t->tptr == NULL)
	return 0;

    err = k5_mutex_lock(&cc_typelist_lock);
    if (err)
	goto errout;
    *ops = t->tptr->ops;
    t->tptr = t->tptr->next;
    err = k5_mutex_unlock(&cc_typelist_lock);
    if (err)
	goto errout;

errout:
    return err;
}

krb5_error_code
krb5int_cc_typecursor_free(krb5_context context, krb5_cc_typecursor *t)
{
    free(*t);
    *t = NULL;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_cc_move (krb5_context context, krb5_ccache src, krb5_ccache dst)
{
    krb5_error_code ret = 0;
    krb5_principal princ = NULL;
    
    ret = krb5_cccol_lock(context);
    if (ret) {
		return ret;
    }
    
    ret = krb5_cc_lock(context, src);
    if (ret) {
		krb5_cccol_unlock(context);
		return ret;
    }
    
    ret = krb5_cc_get_principal(context, src, &princ);
    if (!ret) {
		ret = krb5_cc_initialize(context, dst, princ);
    }
    if (!ret) {
		ret = krb5_cc_lock(context, dst);
    }
    if (!ret) {
		ret = krb5_cc_copy_creds(context, src, dst);
		krb5_cc_unlock(context, dst);
    }
    
    krb5_cc_unlock(context, src);
    if (!ret) {
		ret = krb5_cc_destroy(context, src);
    }
    krb5_cccol_unlock(context);
    if (princ) {
		krb5_free_principal(context, princ);
		princ = NULL;
    }        
    
    return ret;
}

krb5_error_code
k5_cc_mutex_init(k5_cc_mutex *m)
{
    krb5_error_code ret = 0;
    
    ret = k5_mutex_init(&m->lock);
    if (ret) return ret;
    m->owner = NULL;
    m->refcount = 0;
    
    return ret;
}

krb5_error_code
k5_cc_mutex_finish_init(k5_cc_mutex *m)
{
    krb5_error_code ret = 0;
    
    ret = k5_mutex_finish_init(&m->lock);
    if (ret) return ret;
    m->owner = NULL;
    m->refcount = 0;
    
    return ret;
}

void
k5_cc_mutex_assert_locked(krb5_context context, k5_cc_mutex *m)
{
#ifdef DEBUG_THREADS
    assert(m->refcount > 0);
    assert(m->owner == context);
#endif
    k5_assert_locked(&m->lock);
}

void
k5_cc_mutex_assert_unlocked(krb5_context context, k5_cc_mutex *m)
{
#ifdef DEBUG_THREADS
    assert(m->refcount == 0);
    assert(m->owner == NULL);
#endif
    k5_assert_unlocked(&m->lock);    
}

krb5_error_code
k5_cc_mutex_lock(krb5_context context, k5_cc_mutex *m)
{
    krb5_error_code ret = 0;
    
    // not locked or already locked by another context
    if (m->owner != context) {
	// acquire lock, blocking until available
	ret = k5_mutex_lock(&m->lock);
	m->owner = context;
	m->refcount = 1;
    }
    // already locked by this context, just increase refcount
    else {
	m->refcount++;
    }
    return ret;    
}

krb5_error_code
k5_cc_mutex_unlock(krb5_context context, k5_cc_mutex *m)
{
    krb5_error_code ret = 0;
    
    /* verify owner and sanity check refcount */
    if ((m->owner != context) || (m->refcount < 1)) {
	return ret;
    }
    /* decrement & unlock when count reaches zero */
    m->refcount--;
    if (m->refcount == 0) {
	m->owner = NULL;
	k5_mutex_unlock(&m->lock);
    }
    return ret;
}

/* necessary to make reentrant locks play nice with krb5int_cc_finalize */
krb5_error_code
k5_cc_mutex_force_unlock(k5_cc_mutex *m)
{
    krb5_error_code ret = 0;
    
    m->refcount = 0;
    m->owner = NULL;
    if (m->refcount > 0) {
	k5_mutex_unlock(&m->lock);
    }
    return ret;    
}

/*
 * holds on to all pertype global locks as well as typelist lock
 */

krb5_error_code KRB5_CALLCONV
krb5_cccol_lock(krb5_context context)
{
    krb5_error_code ret = 0;
    
    ret = k5_cc_mutex_lock(context, &cccol_lock);
    if (ret) {
	return ret;
    }    
    ret = k5_mutex_lock(&cc_typelist_lock);
    if (ret) {
	k5_cc_mutex_unlock(context, &cccol_lock);
	return ret;
    }
    ret = k5_cc_mutex_lock(context, &krb5int_cc_file_mutex);
    if (ret) {
	k5_mutex_unlock(&cc_typelist_lock);
	k5_cc_mutex_unlock(context, &cccol_lock);
	return ret;
    }
    ret = k5_cc_mutex_lock(context, &krb5int_mcc_mutex);
    if (ret) {
	k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
	k5_mutex_unlock(&cc_typelist_lock);
	k5_cc_mutex_unlock(context, &cccol_lock);
	return ret;
    }
#ifdef USE_CCAPI_V3
    ret = krb5_stdccv3_context_lock(context);
#endif
#ifdef USE_KEYRING_CCACHE
    ret = k5_cc_mutex_lock(context, &krb5int_krcc_mutex);
#endif
    if (ret) {
	k5_cc_mutex_unlock(context, &krb5int_mcc_mutex);
	k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
	k5_mutex_unlock(&cc_typelist_lock);
	k5_cc_mutex_unlock(context, &cccol_lock);
	return ret;
    }
    k5_mutex_unlock(&cc_typelist_lock);
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_cccol_unlock(krb5_context context)
{
    krb5_error_code ret = 0;
    
    /* sanity check */
    k5_cc_mutex_assert_locked(context, &cccol_lock);
    
    ret = k5_mutex_lock(&cc_typelist_lock);
    if (ret) {
	k5_cc_mutex_unlock(context, &cccol_lock);
	return ret;
    }    

    // unlock each type in the opposite order
#ifdef USE_KEYRING_CCACHE
    k5_cc_mutex_assert_locked(context, &krb5int_krcc_mutex);
    k5_cc_mutex_unlock(context, &krb5int_krcc_mutex);
#endif
#ifdef USE_CCAPI_V3
    krb5_stdccv3_context_unlock(context);
#endif
    k5_cc_mutex_assert_locked(context, &krb5int_mcc_mutex);
    k5_cc_mutex_unlock(context, &krb5int_mcc_mutex);
    k5_cc_mutex_assert_locked(context, &krb5int_cc_file_mutex);
    k5_cc_mutex_unlock(context, &krb5int_cc_file_mutex);
    k5_mutex_assert_locked(&cc_typelist_lock);

    k5_mutex_unlock(&cc_typelist_lock);
    k5_cc_mutex_unlock(context, &cccol_lock);

    return ret;
}

/* necessary to make reentrant locks play nice with krb5int_cc_finalize */
krb5_error_code
k5_cccol_force_unlock()
{
    krb5_error_code ret = 0;
    
    /* sanity check */
    if ((&cccol_lock)->refcount == 0) {
	return 0;
    }
    
    ret = k5_mutex_lock(&cc_typelist_lock);
    if (ret) {
	(&cccol_lock)->refcount = 0;
	(&cccol_lock)->owner = NULL;
	k5_mutex_unlock(&(&cccol_lock)->lock);
	return ret;
    }    
    
    // unlock each type in the opposite order
#ifdef USE_KEYRING_CCACHE
    k5_cc_mutex_force_unlock(&krb5int_krcc_mutex);
#endif
#ifdef USE_CCAPI_V3
    krb5_stdccv3_context_unlock(NULL);
#endif
    k5_cc_mutex_force_unlock(&krb5int_mcc_mutex);
    k5_cc_mutex_force_unlock(&krb5int_cc_file_mutex);
    
    k5_mutex_unlock(&cc_typelist_lock);
    k5_cc_mutex_force_unlock(&cccol_lock);
    
    return ret;
}
