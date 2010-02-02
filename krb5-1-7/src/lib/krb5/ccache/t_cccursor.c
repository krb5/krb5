/*
 * lib/krb5/ccache/t_cccursor.c
 *
 * Copyright 2006 by the Massachusetts Institute of Technology.
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
 */

#include "autoconf.h"
#include "krb5.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct crlist {
    char *ccname;
    char *pname;
};

struct crlist crlist[] = {
    { "foo", NULL },
    { "MEMORY:env", "env" },
    { "MEMORY:0", "foo0" },
    { "MEMORY:1", "foo1" },
    { "MEMORY:2", "foo2" },
};
#define NCRLIST (sizeof(crlist)/sizeof(struct crlist))

struct chklist {
    char *pfx;
    char *res;
};

struct chklist chklist0[] = {
    { NULL, NULL },
    { NULL, NULL },
    { "MEMORY", "2" },
    { "MEMORY", "1" },
    { "MEMORY", "0" },
    { "MEMORY", "env" },
};
#define NCHKLIST0 (sizeof(chklist0)/sizeof(struct chklist))

struct chklist chklist1[] = {
    { "MEMORY", "env" },
    { NULL, NULL },
    { "MEMORY", "2" },
    { "MEMORY", "1" },
    { "MEMORY", "0" },
};
#define NCHKLIST1 (sizeof(chklist1)/sizeof(struct chklist))

struct chklist chklist2[] = {
    { "MEMORY", "env" },
    { NULL, NULL },
    { "MEMORY", "2" },
    { "MEMORY", "1" },
    { "MEMORY", "0" },
};
#define NCHKLIST2 (sizeof(chklist2)/sizeof(struct chklist))

krb5_error_code
cr_cache(krb5_context, const char *, const char *);

krb5_error_code
dest_cache(krb5_context, const char *, const char *);

krb5_error_code
do_chk(krb5_context, struct chklist *, int nmax, int *);

int
do_chk_one(const char *, const char *, struct chklist *);

krb5_error_code
cr_cache(krb5_context context, const char *ccname, const char *pname)
{
    krb5_error_code ret;
    krb5_principal princ = NULL;
    krb5_ccache ccache = NULL;

    ret = krb5_cc_resolve(context, ccname, &ccache);
    if (ret)
	goto errout;
    if (pname != NULL) {
	ret = krb5_parse_name(context, pname, &princ);
	if (ret)
	    return ret;
	ret = krb5_cc_initialize(context, ccache, princ);
	if (ret)
	    goto errout;
	printf("created cache %s with principal %s\n", ccname, pname);
    } else
	printf("created cache %s (uninitialized)\n", ccname);
errout:
    if (princ != NULL)
	krb5_free_principal(context, princ);
    if (ccache != NULL)
	krb5_cc_close(context, ccache);
    return ret;
}

krb5_error_code
dest_cache(krb5_context context, const char *ccname, const char *pname)
{
    krb5_error_code ret;
    krb5_ccache ccache = NULL;

    ret = krb5_cc_resolve(context, ccname, &ccache);
    if (ret)
	goto errout;
    if (pname != NULL) {
	ret = krb5_cc_destroy(context, ccache);
	if (ret)
	    return ret;
	printf("Destroyed cache %s\n", ccname);
    } else {
	printf("Closed cache %s (uninitialized)\n", ccname);
	ret = krb5_cc_close(context, ccache);
    }
errout:
    return ret;
}

int
do_chk_one(const char *prefix, const char *name, struct chklist *chk)
{

    if (chk->pfx == NULL)
	return 0;
    if (strcmp(chk->pfx, prefix) || strcmp(chk->res, name)) {
	fprintf(stderr, "MATCH FAILED: expected %s:%s\n",
		chk->pfx, chk->res);
	return 1;
    }
    return 0;
}

krb5_error_code
do_chk(
    krb5_context context,
    struct chklist *chklist,
    int nmax,
    int *good)
{
    krb5_error_code ret = 0;
    krb5_cccol_cursor cursor = NULL;
    krb5_ccache ccache;
    const char *prefix, *name;
    int i;

    ret = krb5_cccol_cursor_new(context, &cursor);
    if (ret) goto errout;

    i = 0;
    printf(">>>\n");
    for (i = 0; ; i++) {
	ret = krb5_cccol_cursor_next(context, cursor, &ccache);
	if (ret) goto errout;
	if (ccache == NULL) {
	    printf("<<< end of list\n");
	    break;
	}
	prefix = krb5_cc_get_type(context, ccache);
	name = krb5_cc_get_name(context, ccache);
	printf("cursor: %s:%s\n", prefix, name);

	if (i < nmax) {
	    if (do_chk_one(prefix, name, &chklist[i])) {
		*good = 0;
	    }
	}
	ret = krb5_cc_close(context, ccache);
	if (ret) goto errout;
    }

    if (i != nmax) {
	fprintf(stderr, "total ccaches %d != expected ccaches %d\n", i, nmax);
	*good = 0;
    }

errout:
    if (cursor != NULL)
	krb5_cccol_cursor_free(context, &cursor);
    return ret;
}

int
main(int argc, char *argv[])
{
    krb5_error_code ret = 0;
    krb5_context context;
    int i, good = 1;

    ret = krb5_init_context(&context);
    if (ret) exit(1);

    for (i = 0; i < NCRLIST; i++) {
	ret = cr_cache(context, crlist[i].ccname, crlist[i].pname);
	if (ret) goto errout;
    }

#ifdef HAVE_SETENV
    setenv("KRB5CCNAME", "foo", 1);
#else
    putenv("KRB5CCNAME=foo");
#endif
    printf("KRB5CCNAME=foo\n");
    ret = do_chk(context, chklist0, NCHKLIST0, &good);
    if (ret)
	goto errout;

#ifdef HAVE_SETENV
    setenv("KRB5CCNAME", "MEMORY:env", 1);
#else
    putenv("KRB5CCNAME=MEMORY:env");
#endif
    printf("KRB5CCNAME=MEMORY:env\n");
    ret = do_chk(context, chklist1, NCHKLIST1, &good);
    if (ret)
	goto errout;

    ret = krb5_cc_set_default_name(context, "MEMORY:env");
    if (ret)
	goto errout;

    printf("KRB5CCNAME=MEMORY:env, ccdefname=MEMORY:env\n");
    ret = do_chk(context, chklist2, NCHKLIST2, &good);
    if (ret)
	goto errout;

    for (i = 0; i < NCRLIST; i++) {
	ret = dest_cache(context, crlist[i].ccname, crlist[i].pname);
	if (ret) goto errout;
    }

errout:
    krb5_free_context(context);
    if (ret) {
	com_err("main", ret, "");
	exit(1);
    } else {
	exit(!good);
    }
}
