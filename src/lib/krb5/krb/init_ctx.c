/*
 * lib/krb5/krb/init_ctx.c
 *
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
 * krb5_init_contex()
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include <ctype.h>
#include "brand.c"

#if (defined(_MSDOS) || defined(_WIN32))
extern krb5_error_code krb5_vercheck();
extern void krb5_win_ccdll_load(krb5_context context);
#endif

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_init_context(context)
	krb5_context *context;
{
	krb5_context ctx = 0;
	krb5_error_code retval;
	krb5_timestamp now;
	krb5_data seed;
	int tmp;

	/* Initialize error tables */
	krb5_init_ets(ctx);

#if (defined(_MSDOS) || defined(_WIN32))
	/*
	 * krb5_vercheck() is defined in win_glue.c, and this is
	 * where we handle the timebomb and version server checks.
	 */
	retval = krb5_vercheck();
	if (retval)
		return retval;
#endif

	*context = 0;

	ctx = malloc(sizeof(struct _krb5_context));
	if (!ctx)
		return ENOMEM;
	memset(ctx, 0, sizeof(struct _krb5_context));
	ctx->magic = KV5M_CONTEXT;

	/* Set the default encryption types, possible defined in krb5/conf */
	if ((retval = krb5_set_default_in_tkt_ktypes(ctx, NULL)))
		goto cleanup;

	if ((retval = krb5_set_default_tgs_ktypes(ctx, NULL)))
		goto cleanup;

	if ((retval = krb5_os_init_context(ctx)))
		goto cleanup;

	/* initialize the prng (not well, but passable) */
	if ((retval = krb5_timeofday(ctx, &now)))
		goto cleanup;
	seed.length = sizeof(now);
	seed.data = (char *) &now;
	if ((retval = krb5_c_random_seed(ctx, &seed)))
		goto cleanup;

	ctx->default_realm = 0;
	profile_get_integer(ctx->profile, "libdefaults", "clockskew",
			    0, 5 * 60, &tmp);
	ctx->clockskew = tmp;

#if 0
	/* Default ticket lifetime is currently not supported */
	profile_get_integer(ctx->profile, "libdefaults", "tkt_lifetime",
			    0, 10 * 60 * 60, &tmp);
	ctx->tkt_lifetime = tmp;
#endif

	/* DCE 1.1 and below only support CKSUMTYPE_RSA_MD4 (2)  */
	/* DCE add kdc_req_checksum_type = 2 to krb5.conf */
	profile_get_integer(ctx->profile, "libdefaults",
			    "kdc_req_checksum_type", 0, CKSUMTYPE_RSA_MD5, 
			    &tmp);
	ctx->kdc_req_sumtype = tmp;

	profile_get_integer(ctx->profile, "libdefaults",
			    "ap_req_checksum_type", 0, CKSUMTYPE_RSA_MD5,
			    &tmp);
	ctx->default_ap_req_sumtype = tmp;

	profile_get_integer(ctx->profile, "libdefaults",
			    "safe_checksum_type", 0,
			    CKSUMTYPE_RSA_MD5_DES, &tmp);
	ctx->default_safe_sumtype = tmp;

	profile_get_integer(ctx->profile, "libdefaults",
			    "kdc_default_options", 0,
			    KDC_OPT_RENEWABLE_OK, &tmp);
	ctx->kdc_default_options = KDC_OPT_RENEWABLE_OK;
#ifdef macintosh
#define DEFAULT_KDC_TIMESYNC 1
#else
#define DEFAULT_KDC_TIMESYNC 0
#endif
	profile_get_integer(ctx->profile, "libdefaults",
			    "kdc_timesync", 0, DEFAULT_KDC_TIMESYNC,
			    &tmp);
	ctx->library_options = tmp ? KRB5_LIBOPT_SYNC_KDCTIME : 0;

	/*
	 * We use a default file credentials cache of 3.  See
	 * lib/krb5/krb/ccache/file/fcc.h for a description of the
	 * credentials cache types.
	 *
	 * Note: DCE 1.0.3a only supports a cache type of 1
	 * 	DCE 1.1 supports a cache type of 2.
	 */
#ifdef macintosh
#define DEFAULT_CCACHE_TYPE 4
#else
#define DEFAULT_CCACHE_TYPE 3
#endif
	profile_get_integer(ctx->profile, "libdefaults", "ccache_type",
			    0, DEFAULT_CCACHE_TYPE, &tmp);
	ctx->fcc_default_format = tmp + 0x0500;
	ctx->scc_default_format = tmp + 0x0500;

#if (defined(_MSDOS) || defined(_WIN32))
	krb5_win_ccdll_load(ctx);	/* Load the krbcc32.dll if necessary */
#endif
	*context = ctx;
	return 0;

cleanup:
	krb5_free_context(ctx);
	return retval;
}

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_context(ctx)
	krb5_context	ctx;
{
     krb5_free_ets(ctx);
     krb5_os_free_context(ctx);

     if (ctx->in_tkt_ktypes) {
          free(ctx->in_tkt_ktypes);
	  ctx->in_tkt_ktypes = 0;
     }

     if (ctx->tgs_ktypes) {
          free(ctx->tgs_ktypes);
	  ctx->tgs_ktypes = 0;
     }

     if (ctx->default_realm) {
	  free(ctx->default_realm);
	  ctx->default_realm = 0;
     }

     if (ctx->ser_ctx_count && ctx->ser_ctx) {
	  free(ctx->ser_ctx);
	  ctx->ser_ctx = 0;
     }

     ctx->magic = 0;
     free(ctx);
}

/*
 * Set the desired default ktypes, making sure they are valid.
 */
krb5_error_code
krb5_set_default_in_tkt_ktypes(context, ktypes)
	krb5_context context;
	const krb5_enctype *ktypes;
{
    krb5_enctype * new_ktypes;
    int i;

    if (ktypes) {
	for (i = 0; ktypes[i]; i++) {
	    if (!valid_enctype(ktypes[i])) 
		return KRB5_PROG_ETYPE_NOSUPP;
	}

	/* Now copy the default ktypes into the context pointer */
	if ((new_ktypes = (krb5_enctype *)malloc(sizeof(krb5_enctype) * i)))
	    memcpy(new_ktypes, ktypes, sizeof(krb5_enctype) * i);
	else
	    return ENOMEM;

    } else {
	i = 0;
	new_ktypes = 0;
    }

    if (context->in_tkt_ktypes) 
        free(context->in_tkt_ktypes);
    context->in_tkt_ktypes = new_ktypes;
    context->in_tkt_ktype_count = i;
    return 0;
}

static krb5_error_code
get_profile_etype_list(context, ktypes, profstr, ctx_count, ctx_list)
     krb5_context context;
     krb5_enctype **ktypes;
     char *profstr;
     int ctx_count;
     krb5_enctype FAR *ctx_list;
{
    krb5_enctype *old_ktypes;

    if (context->in_tkt_ktype_count) {
	/* application-set defaults */
	if ((old_ktypes = 
	     (krb5_enctype *)malloc(sizeof(krb5_enctype) *
				    (ctx_count + 1)))) {
	    memcpy(old_ktypes, ctx_list, sizeof(krb5_enctype) * ctx_count);
	    old_ktypes[ctx_count] = 0;
	} else {
	    return ENOMEM;
	}
    } else {
        /*
	   XXX - For now, we only support libdefaults
	   Perhaps this should be extended to allow for per-host / per-realm
	   session key types.
	 */

	char *retval;
	char *sp, *ep;
	int i, j, count;
	krb5_error_code code;

	code = profile_get_string(context->profile, "libdefaults", profstr,
				  NULL,
				  "des3-hmac-sha1 des-cbc-md5 des-cbc-crc",
				  &retval);
	if (code)
	    return code;

	count = 0;
	sp = retval;
	while (sp) {
	    for (ep = sp; *ep && (*ep != ',') && !isspace(*ep); ep++)
		;
	    if (*ep) {
		*ep++ = '\0';
		while (isspace(*ep))
		    ep++;
	    } else
		ep = (char *) NULL;

	    count++;
	    sp = ep;
	}
	
	if ((old_ktypes =
	     (krb5_enctype *)malloc(sizeof(krb5_enctype) * (count + 1))) ==
	    (krb5_enctype *) NULL)
	    return ENOMEM;
	
	sp = retval;
	j = 0;
	i = 1;
	while (1) {
	    if (! krb5_string_to_enctype(sp, &old_ktypes[j]))
		j++;

	    if (i++ >= count)
		break;

	    /* skip to next token */
	    while (*sp) sp++;
	    while (! *sp) sp++;
	}

	old_ktypes[j] = (krb5_enctype) 0;
	profile_release_string(retval);
    }

    *ktypes = old_ktypes;
    return 0;
}

krb5_error_code
krb5_get_default_in_tkt_ktypes(context, ktypes)
    krb5_context context;
    krb5_enctype **ktypes;
{
    return(get_profile_etype_list(context, ktypes, "default_tkt_enctypes",
				  context->in_tkt_ktype_count,
				  context->in_tkt_ktypes));
}

krb5_error_code
krb5_set_default_tgs_ktypes(context, ktypes)
	krb5_context context;
	const krb5_enctype *ktypes;
{
    krb5_enctype * new_ktypes;
    int i;

    if (ktypes) {
	for (i = 0; ktypes[i]; i++) {
	    if (!valid_enctype(ktypes[i])) 
		return KRB5_PROG_ETYPE_NOSUPP;
	}

	/* Now copy the default ktypes into the context pointer */
	if ((new_ktypes = (krb5_enctype *)malloc(sizeof(krb5_enctype) * i)))
	    memcpy(new_ktypes, ktypes, sizeof(krb5_enctype) * i);
	else
	    return ENOMEM;

    } else {
	i = 0;
	new_ktypes = (krb5_enctype *)NULL;
    }

    if (context->tgs_ktypes) 
        free(context->tgs_ktypes);
    context->tgs_ktypes = new_ktypes;
    context->tgs_ktype_count = i;
    return 0;
}

krb5_error_code
krb5_get_tgs_ktypes(context, princ, ktypes)
    krb5_context context;
    krb5_const_principal princ;
    krb5_enctype **ktypes;
{
    return(get_profile_etype_list(context, ktypes, "default_tgs_enctypes",
				  context->tgs_ktype_count,
				  context->tgs_ktypes));
}

krb5_error_code
krb5_get_permitted_enctypes(context, ktypes)
    krb5_context context;
    krb5_enctype **ktypes;
{
    return(get_profile_etype_list(context, ktypes, "permitted_enctypes",
				  context->tgs_ktype_count,
				  context->tgs_ktypes));
}

krb5_boolean
krb5_is_permitted_enctype(context, etype)
     krb5_context context;
     krb5_enctype etype;
{
    krb5_enctype *list, *ptr;
    krb5_boolean ret;

    if (krb5_get_permitted_enctypes(context, &list))
	return(0);

    
    ret = 0;

    for (ptr = list; *ptr; ptr++)
	if (*ptr == etype)
	    ret = 1;

    krb5_xfree(list);

    return(ret);
}
