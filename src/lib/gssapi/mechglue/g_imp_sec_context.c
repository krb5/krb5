/* #ident  "@(#)g_imp_sec_context.c 1.2     96/01/18 SMI" */

/*
 * Copyright 1996 by Sun Microsystems, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Sun Microsystems not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. Sun Microsystems makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * SUN MICROSYSTEMS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SUN MICROSYSTEMS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 *  glue routine gss_export_sec_context
 */

#include "mglueP.h"
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>

OM_uint32 KRB5_CALLCONV
gss_import_sec_context(minor_status,
                       interprocess_token,
                       context_handle)

OM_uint32 *		minor_status;
gss_buffer_t		interprocess_token;
gss_ctx_id_t *		context_handle;

{
    size_t		length;
    OM_uint32		status;
    char		*p;
    gss_union_ctx_id_t	ctx;
    gss_buffer_desc	token;
    gss_mechanism	mech;
    
    gss_initialize();

    *minor_status = 0;
    
    if (interprocess_token->length == 0 || interprocess_token->value == 0)
	return (GSS_S_DEFECTIVE_TOKEN);

    status = GSS_S_FAILURE;

    ctx = (gss_union_ctx_id_t) malloc(sizeof(gss_union_ctx_id_desc));
    if (!ctx) {
	*minor_status = ENOMEM;
	goto error_out;
    }
    ctx->mech_type = (gss_OID) malloc(sizeof(gss_OID_desc));
    if (!ctx->mech_type) {
	*minor_status = ENOMEM;
	goto error_out;
    }
    p = interprocess_token->value;
    length = *p++;
    length = (length << 8) + *p++;
    length = (length << 8) + *p++;
    length = (length << 8) + *p++;

    ctx->mech_type->length = length;
    ctx->mech_type->elements = malloc(length);
    if (!ctx->mech_type->elements) {
	*minor_status = ENOMEM;
	goto error_out;
    }
    memcpy(ctx->mech_type->elements, p, length);
    p += length;

    token.length = interprocess_token->length - 4 - length;
    token.value = p;

    /*
     * select the approprate underlying mechanism routine and
     * call it.
     */
    
    mech = __gss_get_mechanism (ctx->mech_type);
    if (!mech) {
	status = GSS_S_BAD_MECH;
	goto error_out;
    }
    if (!mech->gss_import_sec_context) {
	status = GSS_S_BAD_BINDINGS;
	goto error_out;
    }
    
    status = mech->gss_import_sec_context(mech->context, minor_status,
					  &token, &ctx->internal_ctx_id);

    if (status == GSS_S_COMPLETE) {
	*context_handle = ctx;
	return (GSS_S_COMPLETE);
    }
    
error_out:
    if (ctx) {
	if (ctx->mech_type) {
	    if (ctx->mech_type->elements)
		free(ctx->mech_type->elements);
	    free(ctx->mech_type);
	}
	free(ctx);
    }
    return status;
}
