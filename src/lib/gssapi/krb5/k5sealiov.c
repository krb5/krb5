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

static krb5_error_code
make_seal_token_v1_iov(krb5_context context,
		       krb5_gss_ctx_id_rec *ctx,
		       int conf_req_flag,
		       size_t iov_count,
		       gss_iov_buffer_desc *iov,
		       int toktype)
{
    krb5_error_code code;
    gss_iov_buffer_t token;
    gss_iov_buffer_t padding;
    krb5_checksum md5cksum;
    krb5_checksum cksum;
    size_t conflen;
    size_t textlen;
    size_t blocksize;
    size_t sumlen;
    size_t tmsglen, tlen;
    unsigned char *ptr;
    krb5_keyusage sign_usage = KG_USAGE_SIGN;

    assert(!conf_req_flag || toktype == KG_TOK_SEAL_MSG);

    md5cksum.length = cksum.length = 0;
    md5cksum.contents = cksum.contents = NULL;

    token = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TOKEN);
    if (token == NULL) {
	return EINVAL;
    }
    padding = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding == NULL) {
	return EINVAL;
    }

    /* Determine confounder length */
    if (conf_req_flag)
	conflen = kg_confounder_size(context, ctx->enc);
    else
	conflen = 0;

    /* Check padding length */

    if (toktype == KG_TOK_SEAL_MSG) {
	textlen = kg_iov_msglen(iov_count, iov, 0);

	switch (ctx->sealalg) {
	case SEAL_ALG_MICROSOFT_RC4:
	    blocksize = 1;
	    break;
	default:
	    blocksize = 8;
	    break;
	}

	/* The caller must correctly pad the input buffer */
	if ((textlen + padding->buffer.length) % blocksize != 0)
	    return KRB5_BAD_MSIZE;

	if (ctx->gss_flags & GSS_C_DCE_STYLE)
	    tmsglen = 0;
	else
	    tmsglen = textlen + padding->buffer.length;
    } else {
	textlen = 0;
	blocksize = 0;
	tmsglen = 0;
    }

    /* Determine token size */
    tlen = g_token_size(ctx->mech_used, 14 + ctx->cksum_size + tmsglen);

    if (token->flags & GSS_IOV_BUFFER_FLAG_ALLOCATE) {
	token->buffer.value = xmalloc(tlen);
	if (token->buffer.value == NULL)
	    return ENOMEM;
	token->flags |= GSS_IOV_BUFFER_FLAG_ALLOCATED;
    } if (token->buffer.length < tlen) {
	return ERANGE;
    }
    token->buffer.length = tlen;

    ptr = (unsigned char *)token->buffer.value;
    g_make_token_header(ctx->mech_used, 14 + ctx->cksum_size + tmsglen, &ptr, toktype);

    /* 0..1 SIGN_ALG */
    ptr[0] = (ctx->signalg     ) & 0xFF;
    ptr[1] = (ctx->signalg >> 8) & 0xFF;

    /* 2..3 SEAL_ALG or Filler */
    if (toktype == KG_TOK_SEAL_MSG && conf_req_flag) {
	ptr[2] = (ctx->sealalg     ) & 0xFF;
	ptr[3] = (ctx->sealalg >> 8) & 0xFF;
    } else {
	/* No seal */
	ptr[2] = 0xFF;
	ptr[3] = 0xFF;
    }

    /* 4..5 Filler */
    ptr[4] = 0xFF;
    ptr[5] = 0xFF;

    /* pad the plaintext, encrypt if needed, and stick it in the token */

    /* initialize the checksum */
    switch (ctx->signalg) {
    case SGN_ALG_DES_MAC_MD5:
    case SGN_ALG_MD2_5:
	md5cksum.checksum_type = CKSUMTYPE_RSA_MD5;
	break;
    case SGN_ALG_HMAC_SHA1_DES3_KD:
	md5cksum.checksum_type = CKSUMTYPE_HMAC_SHA1_DES3;
	break;
    case SGN_ALG_HMAC_MD5:
	md5cksum.checksum_type = CKSUMTYPE_HMAC_MD5_ARCFOUR;
	if (toktype != KG_TOK_SEAL_MSG)
	    sign_usage = 15;
	break;
    default:
    case SGN_ALG_DES_MAC:
	abort ();
    }

    code = krb5_c_checksum_length(context, md5cksum.checksum_type, &sumlen);
    if (code != 0)
	goto cleanup;
    md5cksum.length = sumlen;

    if (conflen != 0) {
	code = kg_make_confounder(context, ctx->enc, ptr + 14 + ctx->cksum_size);
	if (code != 0)
	    goto cleanup;
    }

    /* initialize the pad */
    memset(padding->buffer.value, blocksize, padding->buffer.length);

    /* compute the checksum */
    code = kg_checksum_iov(context, md5cksum.checksum_type, ctx->seq, ctx->enc,
			   sign_usage, iov_count, iov, &md5cksum);
    if (code != 0)
	goto cleanup;

    switch (ctx->signalg) {
    case SGN_ALG_DES_MAC_MD5:
    case SGN_ALG_3:
	code = kg_encrypt(context, ctx->seq, KG_USAGE_SEAL,
			  (g_OID_equal(ctx->mech_used, gss_mech_krb5_old) ?
			   ctx->seq->contents : NULL),
			  md5cksum.contents, md5cksum.contents, 16);
	if (code != 0)
	    goto cleanup;
	break;

	cksum.length = ctx->cksum_size;
	cksum.contents = md5cksum.contents + 16 - cksum.length;

	memcpy(ptr + 14, cksum.contents, cksum.length);
    case SGN_ALG_HMAC_SHA1_DES3_KD:
	assert(md5cksum.length == ctx->cksum_size);
	memcpy(ptr + 14, md5cksum.contents, md5cksum.length);
	break;
    case SGN_ALG_HMAC_MD5:
	memcpy(ptr + 14, md5cksum.contents, ctx->cksum_size);
	break;
    }

    /* create the seq_num */

    code = kg_make_seq_num(context, ctx->seq, ctx->initiate ? 0 : 0xFF, ctx->seq_send,
			   ptr + 14, ptr + 6);
    if (code != 0)
	goto cleanup;

    if (conf_req_flag) {
	switch (ctx->sealalg) {
	case SEAL_ALG_MICROSOFT_RC4:
	{
	    unsigned char bigend_seqnum[4];
	    krb5_keyblock *enc_key;
	    int i;

	    bigend_seqnum[0] = (ctx->seq_send >> 24) & 0xFF;
	    bigend_seqnum[1] = (ctx->seq_send >> 16) & 0xFF;
	    bigend_seqnum[2] = (ctx->seq_send >> 8 ) & 0xFF;
	    bigend_seqnum[3] = (ctx->seq_send      ) & 0xFF;

	    code = krb5_copy_keyblock(context, ctx->enc, &enc_key);
	    if (code != 0)
		goto cleanup;

	    assert(enc_key->length == 16);

	    for (i = 0; i < enc_key->length; i++)
		((char *)enc_key->contents)[i] ^= 0xF0;

	    code = kg_arcfour_docrypt_iov(context, enc_key, 0,
					  bigend_seqnum, 4,
					  iov_count, iov);
	    krb5_free_keyblock(context, enc_key);
	    if (code != 0)
		goto cleanup;

	    break;
	default:
	    code = kg_encrypt_iov(context, ctx->enc, KG_USAGE_SEAL, NULL,
				  iov_count, iov);
	    if (code != 0)
		goto cleanup;
	    break;
	}
	}
    }

    ctx->seq_send++;
    ctx->seq_send &= 0xFFFFFFFFL;

    code = 0;

cleanup:
    kg_release_iov(iov_count, iov);
    krb5_free_checksum_contents(context, &md5cksum);

    return code;
}

OM_uint32
kg_seal_iov(OM_uint32 *minor_status,
	    gss_ctx_id_t context_handle,
	    int conf_req_flag,
	    gss_qop_t qop_req,
	    int *conf_state,
	    size_t iov_count,
	    gss_iov_buffer_desc *iov,
	    int toktype)
{
    krb5_gss_ctx_id_rec *ctx;
    krb5_error_code code;
    krb5_timestamp now;
    krb5_context context;

    if (qop_req != 0) {
	*minor_status = (OM_uint32)G_UNKNOWN_QOP;
	return GSS_S_FAILURE;
    }

    if (!kg_validate_ctx_id(context_handle)) {
	*minor_status = (OM_uint32)G_VALIDATE_FAILED;
	return GSS_S_NO_CONTEXT;
    }

    ctx = (krb5_gss_ctx_id_rec *)context_handle;
    if (!ctx->established) {
	*minor_status = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    context = ctx->k5_context;
    code = krb5_timeofday(context, &now);
    if (code != 0) {
	*minor_status = code;
	save_error_info(*minor_status, context);
	return GSS_S_FAILURE;
    }

    switch (ctx->proto) {
    case 0:
	code = make_seal_token_v1_iov(context, ctx, conf_req_flag, iov_count, iov, toktype);
	break;
    case 1:
    default:
	code = G_UNKNOWN_QOP;
	break;
    }

    if (code != 0) {
	*minor_status = 0;
	save_error_info(*minor_status, context);
	return GSS_S_FAILURE;
    }

    if (conf_state != NULL)
	*conf_state = conf_req_flag;

    *minor_status = 0;

    return (ctx->endtime < now) ? GSS_S_CONTEXT_EXPIRED : GSS_S_COMPLETE;
}

