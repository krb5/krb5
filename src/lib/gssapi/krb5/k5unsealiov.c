/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * lib/gssapi/krb5/k5sealiov.c
 *
 * Copyright 2008 by the Massachusetts Institute of Technology.
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
 */

#include <assert.h>
#include "k5-platform.h"	/* for 64-bit support */
#include "k5-int.h"	     /* for zap() */
#include "gssapiP_krb5.h"
#include <stdarg.h>


OM_uint32
kg_unseal_iov(OM_uint32 *minor_status,
	      gss_ctx_id_t context_handle,
	      int *conf_state,
	      gss_qop_t *qop_state,
	      size_t iov_count,
	      gss_iov_buffer_desc *iov,
	      int toktype)
{
    krb5_gss_ctx_id_rec *ctx;
    krb5_error_code code;
    krb5_context context;
    unsigned char *ptr;
    int toktype2;
    gss_iov_buffer_t token;
    gss_iov_buffer_t padding;
    size_t input_length;
    unsigned int bodysize;

    if (!kg_validate_ctx_id(context_handle)) {
	*minor_status = (OM_uint32)G_VALIDATE_FAILED;
	return GSS_S_NO_CONTEXT;
    }

    ctx = (krb5_gss_ctx_id_rec *)context_handle;
    if (!ctx->established) {
	*minor_status = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    *minor_status = 0;

    token = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TOKEN);
    if (token == NULL)
	return GSS_S_DEFECTIVE_TOKEN;

    padding = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding == NULL)
	return GSS_S_DEFECTIVE_TOKEN;

    ptr = (unsigned char *)token->buffer.value;
    if (ctx->proto) {
	switch (toktype) {
	case KG_TOK_SIGN_MSG:
	    toktype2 = 0x0404;
	    break;
	case KG_TOK_SEAL_MSG:
	    toktype2 = 0x0504;
	    break;
	case KG_TOK_DEL_CTX:
	    toktype2 = 0x040f;
	    break;
	default:
	    toktype2 = toktype;
	    break;
	}
    } else
	toktype2 = toktype;

    input_length = token->buffer.length + kg_iov_msglen(iov_count, iov, 0) + padding->buffer.length;

    code = g_verify_token_header(ctx->mech_used,
				 &bodysize, &ptr, toktype2,
				 input_length, !ctx->proto);
    if (code != 0) {
	*minor_status = code;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (ctx->proto == 0)
	;
    else
	;

    if (code != 0)
	save_error_info(*minor_status, context);

    return code;
}

