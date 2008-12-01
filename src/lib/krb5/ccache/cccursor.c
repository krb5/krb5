/*
 * lib/krb5/ccache/cccursor.c
 *
 * Copyright 2006, 2007 by the Massachusetts Institute of Technology.
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
 * cursor for sequential traversal of ccaches
 */

#include "cc-int.h"

#include <assert.h>

#define CCCURSOR_CONTEXT 1
#define CCCURSOR_ENV 2
#define CCCURSOR_OS 3
#define CCCURSOR_PERTYPE 4

#define NFULLNAMES 3

/* Prefix and residual parts of a full ccache name. */
struct cc_fullname {
    char *pfx;
    char *res;
};

struct _krb5_cccol_cursor {
    int pos;
    krb5_cc_typecursor typecursor;
    const krb5_cc_ops *ops;
    krb5_cc_ptcursor ptcursor;
    int cur_fullname;
    struct cc_fullname fullnames[NFULLNAMES]; /* previously seen ccaches */
};
/* typedef of krb5_cccol_cursor is in krb5.h */

static int cccol_already(krb5_context, krb5_cccol_cursor, krb5_ccache *);

static int cccol_cmpname(const char *, const char *, struct cc_fullname *);

static krb5_error_code
cccol_do_resolve(krb5_context, krb5_cccol_cursor, const char *, krb5_ccache *);

static krb5_error_code
cccol_pertype_next(krb5_context, krb5_cccol_cursor, krb5_ccache *);

krb5_error_code KRB5_CALLCONV
krb5_cccol_cursor_new(
    krb5_context context,
    krb5_cccol_cursor *cursor)
{
    krb5_error_code ret = 0;
    krb5_cccol_cursor n = NULL;
    int i;

    *cursor = NULL;
    n = malloc(sizeof(*n));
    if (n == NULL)
	return ENOMEM;

    n->pos = CCCURSOR_CONTEXT;
    n->typecursor = NULL;
    n->ptcursor = NULL;
    n->ops = NULL;

    for (i = 0; i < NFULLNAMES; i++) {
	n->fullnames[i].pfx = n->fullnames[i].res = NULL;
    }
    n->cur_fullname = 0;
    ret = krb5int_cc_typecursor_new(context, &n->typecursor);
    if (ret)
	goto errout;

    do {
	/* Find first backend with ptcursor functionality. */
	ret = krb5int_cc_typecursor_next(context, n->typecursor, &n->ops);
	if (ret || n->ops == NULL)
	    goto errout;
    } while (n->ops->ptcursor_new == NULL);

    ret = n->ops->ptcursor_new(context, &n->ptcursor);
    if (ret)
	goto errout;

errout:
    if (ret) {
	krb5_cccol_cursor_free(context, &n);
    }
    *cursor = n;
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_cccol_cursor_next(
    krb5_context context,
    krb5_cccol_cursor cursor,
    krb5_ccache *ccache)
{
    krb5_error_code ret = 0;
    char *name;
    krb5_os_context os_ctx = NULL;

    *ccache = NULL;
    os_ctx = &context->os_context;

    switch (cursor->pos) {
    case CCCURSOR_CONTEXT:
	name = os_ctx->default_ccname;
	if (name != NULL) {
	    cursor->pos = CCCURSOR_ENV;
	    ret = cccol_do_resolve(context, cursor, name, ccache);
	    if (ret)
		goto errout;
	    if (*ccache != NULL)
		break;
	}
	/* fall through */
    case CCCURSOR_ENV:
	name = getenv(KRB5_ENV_CCNAME);
	if (name != NULL) {
	    cursor->pos = CCCURSOR_OS;
	    ret = cccol_do_resolve(context, cursor, name, ccache);
	    if (ret)
		goto errout;
	    if (*ccache != NULL)
		break;
	}
	/* fall through */
    case CCCURSOR_OS:
	ret = krb5int_cc_os_default_name(context, &name);
	if (ret) goto errout;
	if (name != NULL) {
	    cursor->pos = CCCURSOR_PERTYPE;
	    ret = cccol_do_resolve(context, cursor, name, ccache);
	    free(name);
	    if (ret)
		goto errout;
	    if (*ccache != NULL)
		break;
	}
	/* fall through */
    case CCCURSOR_PERTYPE:
	cursor->pos = CCCURSOR_PERTYPE;
	do {
	    ret = cccol_pertype_next(context, cursor, ccache);
	    if (ret)
		goto errout;
	} while (cccol_already(context, cursor, ccache));
	break;
    }
errout:
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_cccol_cursor_free(
    krb5_context context,
    krb5_cccol_cursor *cursor)
{
    krb5_cccol_cursor c = *cursor;
    int i;

    if (c == NULL)
	return 0;

    for (i = 0; i < NFULLNAMES; i++) {
	if (c->fullnames[i].pfx != NULL)
	    free(c->fullnames[i].pfx);
	if (c->fullnames[i].res != NULL)
	    free(c->fullnames[i].res);
    }
    if (c->ptcursor != NULL)
	c->ops->ptcursor_free(context, &c->ptcursor);
    if (c->typecursor != NULL)
	krb5int_cc_typecursor_free(context, &c->typecursor);
    free(c);

    *cursor = NULL;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_cccol_last_change_time(
    krb5_context context, 
    krb5_timestamp *change_time)
{
    krb5_error_code ret = 0;
    krb5_cccol_cursor c = NULL;
    krb5_ccache ccache = NULL;
    krb5_timestamp last_time = 0;
    krb5_timestamp max_change_time = 0;
    
    *change_time = 0;
    
    ret = krb5_cccol_cursor_new(context, &c);
    
    while (!ret) {
        ret = krb5_cccol_cursor_next(context, c, &ccache);
        if (ccache) {
            ret = krb5_cc_last_change_time(context, ccache, &last_time);
            if (!ret && last_time > max_change_time) {
                max_change_time = last_time;
            }
            ret = 0;
        }
        else {
            break;
        }
    }
    *change_time = max_change_time;
    return ret;
}

/*
 * krb5_cccol_lock and krb5_cccol_unlock are defined in ccbase.c
 */

/*
 * Determine if a ccache from a per-type cursor was already one of the
 * higher-priority defaults.
 */
static int
cccol_already(
    krb5_context context,
    krb5_cccol_cursor c,
    krb5_ccache *ccache)
{
    const char *name = NULL, *prefix = NULL;
    int i;

    if (*ccache == NULL)
	return 0;
    name = krb5_cc_get_name(context, *ccache);
    if (name == NULL)
	return 0;
    prefix = krb5_cc_get_type(context, *ccache);

    assert(c->cur_fullname < NFULLNAMES);
    for (i = 0; i < c->cur_fullname; i++) {
	if (cccol_cmpname(prefix, name, &c->fullnames[i])) {
	    krb5_cc_close(context, *ccache);
	    *ccache = NULL;
	    return 1;
	}
    }
    return 0;
}

/*
 * Compare {prefix, name} against a cc_fullname.
 */
static int
cccol_cmpname(
    const char *prefix,
    const char *name,
    struct cc_fullname *fullname)
{
    if (fullname->pfx == NULL || fullname->res == NULL)
	return 0;
    if (strcmp(prefix, fullname->pfx))
	return 0;
    if (strcmp(name, fullname->res))
	return 0;

    return 1;
}

/*
 * Resolve one of the high-precedence ccaches, and cache its full name
 * {prefix, residual} for exclusion when doing per-type ccache
 * iteration.  Also check to see if we've already seen the ccache
 * name we're given.
 */
static krb5_error_code
cccol_do_resolve(
    krb5_context context,
    krb5_cccol_cursor cursor,
    const char *name,
    krb5_ccache *ccache)
{
    krb5_error_code ret = 0;
    struct cc_fullname *fullname;

    assert(cursor->cur_fullname < NFULLNAMES);
    ret = krb5_cc_resolve(context, name, ccache);
    if (ret)
	return ret;

    if (cccol_already(context, cursor, ccache))
	return 0;

    fullname = &cursor->fullnames[cursor->cur_fullname];
    fullname->pfx = strdup(krb5_cc_get_type(context, *ccache));
    fullname->res = strdup(krb5_cc_get_name(context, *ccache));
    cursor->cur_fullname++;
    return ret;
}

/*
 * Find next ccache in current backend, iterating through backends if
 * ccache list of the current backend is exhausted.
 */
static krb5_error_code
cccol_pertype_next(
    krb5_context context,
    krb5_cccol_cursor cursor,
    krb5_ccache *ccache)
{
    krb5_error_code ret = 0;

    *ccache = NULL;

    /* Are we out of backends? */
    if (cursor->ops == NULL)
	return 0;
    /*
     * Loop in case there are multiple backends with empty ccache
     * lists.
     */
    while (*ccache == NULL) {
	ret = cursor->ops->ptcursor_next(context, cursor->ptcursor, ccache);
	if (ret)
	    goto errout;
	if (*ccache != NULL)
	    return 0;

	ret = cursor->ops->ptcursor_free(context, &cursor->ptcursor);
	if (ret)
	    goto errout;

	do {
	    /* Find first backend with ptcursor functionality. */
	    ret = krb5int_cc_typecursor_next(context, cursor->typecursor,
					     &cursor->ops);
	    if (ret)
		goto errout;
	    if (cursor->ops == NULL)
		return 0;
	} while (cursor->ops->ptcursor_new == NULL);

	ret = cursor->ops->ptcursor_new(context, &cursor->ptcursor);
	if (ret)
	    goto errout;
    }
errout:
    return ret;
}
