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
    krb5_context	context = ct;
    krb5_error_code	kret;
    OM_uint32		retval;
    krb5_context	ser_ctx;
    size_t		bufsize, blen;
    krb5_gss_ctx_id_t	*ctx;
    krb5_octet		*obuffer, *obp;

    /* Assume a tragic failure */
    ser_ctx = (krb5_context) NULL;
    obuffer = (krb5_octet *) NULL;
    retval = GSS_S_FAILURE;
    *minor_status = 0;

    /* Get a fresh Kerberos context */
    if (!(kret = krb5_init_context(&ser_ctx))) {
	/* Initialize the serializers */
	if (!(kret = krb5_ser_context_init(ser_ctx)) &&
	    !(kret = krb5_ser_auth_context_init(ser_ctx)) &&
	    !(kret = krb5_ser_ccache_init(ser_ctx)) &&
	    !(kret = krb5_ser_rcache_init(ser_ctx)) &&
	    !(kret = krb5_ser_keytab_init(ser_ctx)) &&
	    !(kret = kg_ser_context_init(ser_ctx))) {
	    if (kg_validate_ctx_id(*context_handle)) {
		ctx = (krb5_gss_ctx_id_t *) *context_handle;

		/* Determine size needed for externalization of context */
		bufsize = 0;
		if (!(kret = krb5_size_opaque(ser_ctx,
					      KG_CONTEXT,
					      (krb5_pointer) ctx,
					      &bufsize))) {
		    /* Allocate the buffer */
		    if ((obuffer = (krb5_octet *) xmalloc(bufsize))) {
			obp = obuffer;
			blen = bufsize;
			/* Externalize the context */
			if (!(kret = krb5_externalize_opaque(ser_ctx,
							     KG_CONTEXT,
							     (krb5_pointer)ctx,
							     &obp,
							     &blen))) {
			    /* Success!  Return the buffer */
			    interprocess_token->length = bufsize - blen;
			    interprocess_token->value = obuffer;
			    *minor_status = 0;
			    retval = GSS_S_COMPLETE;

			    /* Now, clean up the context state */
			    (void) kg_delete_ctx_id((gss_ctx_id_t) ctx);
			    if (ctx->enc.processed)
				krb5_finish_key(context,
						&ctx->enc.eblock);
			    krb5_free_keyblock(context, ctx->enc.key);
			    if (ctx->seq.processed)
				krb5_finish_key(context,
						&ctx->seq.eblock);
			    krb5_free_keyblock(context, ctx->seq.key);
			    krb5_free_principal(context, ctx->here);
			    krb5_free_principal(context, ctx->there);
			    krb5_free_keyblock(context, ctx->subkey);

			    if (ctx->auth_context)
				krb5_auth_con_free(context, ctx->auth_context);

			    /* Zero out context */
			    memset(ctx, 0, sizeof(*ctx));
			    xfree(ctx);
			    *context_handle = GSS_C_NO_CONTEXT;
			}
		    }
		}
	    }
	    else {
		*minor_status = (OM_uint32) G_VALIDATE_FAILED;
		retval = GSS_S_NO_CONTEXT;
	    }
	}
	krb5_free_context(ser_ctx);
    }
    if (retval != GSS_S_COMPLETE) {
	if (obuffer && bufsize) {
	    memset(obuffer, 0, bufsize);
	    krb5_xfree(obuffer);
	}
	if (*minor_status == 0) 
	    *minor_status = (OM_uint32) kret;
    }
    return(retval);
}
