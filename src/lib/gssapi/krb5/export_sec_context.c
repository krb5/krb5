/*
 * lib/gssapi/krb5/export_sec_context.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */

/*
 * export_sec_context.c	- Externalize the security context.
 */
#include "gssapiP_krb5.h"

OM_uint32
krb5_gss_export_sec_context(ct,
			    minor_status, context_handle, interprocess_token)
    void		*ct;
    OM_uint32		*minor_status;
    gss_ctx_id_t	*context_handle;
    gss_buffer_t	interprocess_token;
{
    krb5_context	ser_ctx = ct;
    krb5_error_code	kret;
    OM_uint32		retval;
    size_t		bufsize, blen;
    krb5_gss_ctx_id_t	*ctx;
    krb5_octet		*obuffer, *obp;

    /* Assume a tragic failure */
    obuffer = (krb5_octet *) NULL;
    retval = GSS_S_FAILURE;
    *minor_status = 0;

    if (!kg_validate_ctx_id(*context_handle)) {
	    kret = (OM_uint32) G_VALIDATE_FAILED;
	    retval = GSS_S_NO_CONTEXT;
	    goto error_out;
    }

    ctx = (krb5_gss_ctx_id_t *) *context_handle;

    /* Determine size needed for externalization of context */
    bufsize = 0;
    if ((kret = krb5_size_opaque(ser_ctx, KG_CONTEXT, (krb5_pointer) ctx,
				  &bufsize)))
	    goto error_out;

    /* Allocate the buffer */
    if ((obuffer = (krb5_octet *) xmalloc(bufsize)) == NULL) {
	    kret = ENOMEM;
	    goto error_out;
    }

    obp = obuffer;
    blen = bufsize;
    /* Externalize the context */
    if ((kret = krb5_externalize_opaque(ser_ctx, KG_CONTEXT,
					(krb5_pointer)ctx, &obp, &blen)))
	    goto error_out;

    /* Success!  Return the buffer */
    interprocess_token->length = bufsize - blen;
    interprocess_token->value = obuffer;
    *minor_status = 0;
    retval = GSS_S_COMPLETE;

    /* Now, clean up the context state */
    (void) kg_delete_ctx_id((gss_ctx_id_t) ctx);
    if (ctx->enc.processed)
	    krb5_finish_key(ser_ctx, &ctx->enc.eblock);
    krb5_free_keyblock(ser_ctx, ctx->enc.key);
    if (ctx->seq.processed)
	    krb5_finish_key(ser_ctx, &ctx->seq.eblock);
    krb5_free_keyblock(ser_ctx, ctx->seq.key);
    krb5_free_principal(ser_ctx, ctx->here);
    krb5_free_principal(ser_ctx, ctx->there);
    krb5_free_keyblock(ser_ctx, ctx->subkey);

    if (ctx->auth_context)
	    krb5_auth_con_free(ser_ctx, ctx->auth_context);

    /* Zero out context */
    memset(ctx, 0, sizeof(*ctx));
    xfree(ctx);
    *context_handle = GSS_C_NO_CONTEXT;

    return (GSS_S_COMPLETE);

error_out:
    if (obuffer && bufsize) {
	    memset(obuffer, 0, bufsize);
	    krb5_xfree(obuffer);
    }
    if (*minor_status == 0) 
	    *minor_status = (OM_uint32) kret;
    return(retval);
}
