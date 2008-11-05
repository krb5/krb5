/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * lib/gssapi/krb5/k5unsealiov.c
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

static OM_uint32
kg_unseal_v1_iov(krb5_context context,
		 OM_uint32 *minor_status,
		 krb5_gss_ctx_id_rec *ctx,
		 size_t iov_count,
		 gss_iov_buffer_desc *iov,
		 int *conf_state,
		 gss_qop_t *qop_state,
		 int toktype)
{
    krb5_error_code code;
    gss_iov_buffer_t token;
    unsigned char *ptr;
    int sealalg;
    int signalg;
    krb5_checksum cksum;
    krb5_checksum md5cksum;
    krb5_timestamp now;
    size_t cksum_len = 0;
    size_t conflen;
    int direction;
    krb5_ui_4 seqnum;
    OM_uint32 retval;
    size_t sumlen;
    krb5_keyusage sign_usage = KG_USAGE_SIGN;

    md5cksum.length = cksum.length = 0;
    md5cksum.contents = cksum.contents = NULL;

    token = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TOKEN);
    assert(token != NULL);

    if (token->buffer.length < 16) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    ptr = ((unsigned char *)token->buffer.value) + 2; /* skip past TOK_ID */
   
    signalg  = ptr[0];
    signalg |= ptr[1] << 8;

    sealalg  = ptr[2];
    sealalg |= ptr[3] << 8;

    if (ptr[4] != 0xFF || ptr[5] != 0xFF) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (toktype != KG_TOK_SEAL_MSG && sealalg != 0xFFFF) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (toktype == KG_TOK_SEAL_MSG &&
	!(sealalg == 0xFFFF || sealalg == ctx->sealalg)) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if ((ctx->sealalg == SEAL_ALG_NONE && signalg > 1) ||
	(ctx->sealalg == SEAL_ALG_1 && signalg != SGN_ALG_3) ||
	(ctx->sealalg == SEAL_ALG_DES3KD &&
	 signalg != SGN_ALG_HMAC_SHA1_DES3_KD)||
	(ctx->sealalg == SEAL_ALG_MICROSOFT_RC4 &&
	 signalg != SGN_ALG_HMAC_MD5)) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    switch (signalg) {
    case SGN_ALG_DES_MAC_MD5:
    case SGN_ALG_MD2_5:
    case SGN_ALG_HMAC_MD5:
	cksum_len = 8;
	if (toktype != KG_TOK_SEAL_MSG)
	    sign_usage = 15;
	break;
    case SGN_ALG_3:
	cksum_len = 16;
	break;
    case SGN_ALG_HMAC_SHA1_DES3_KD:
	cksum_len = 20;
	break;
    default:
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    /* get the token parameters */
    code = kg_get_seq_num(context, ctx->seq, ptr + 14, ptr + 6, &direction,
			  &seqnum);
    if (code != 0) {
	*minor_status = code;
	return GSS_S_BAD_SIG;
    }

    /* decode the message, if SEAL */
    if (toktype == KG_TOK_SEAL_MSG) {
	if (sealalg != 0xFFFF) {
	    if (ctx->enc->enctype == ENCTYPE_ARCFOUR_HMAC) {
		unsigned char bigend_seqnum[4];
		krb5_keyblock *enc_key;
		int i;

		bigend_seqnum[0] = (seqnum >> 24) & 0xFF;
		bigend_seqnum[1] = (seqnum >> 16) & 0xFF;
		bigend_seqnum[2] = (seqnum >> 8 ) & 0xFF;
		bigend_seqnum[3] = (seqnum      ) & 0xFF;

		code = krb5_copy_keyblock(context, ctx->enc, &enc_key);
		if (code != 0) {
		    retval = GSS_S_FAILURE;
		    goto cleanup;
		}

		assert(enc_key->length == 16);

		for (i = 0; i < enc_key->length; i++)
		    ((char *)enc_key->contents)[i] ^= 0xF0;

		code = kg_arcfour_docrypt_iov(context, enc_key, 0,
					      &bigend_seqnum[0], 4,
					      iov_count, iov);
		krb5_free_keyblock(context, enc_key);
	    } else {
		code = kg_decrypt_iov(context, ctx->enc, KG_USAGE_SEAL, NULL,
				      iov_count, iov);
	    }
	    if (code != 0) {
		retval = GSS_S_FAILURE;
		goto cleanup;
	    }
	}

	assert(ctx->big_endian == 0);

	conflen = kg_confounder_size(context, ctx->enc);

	if (token->buffer.length != 16 + cksum_len + conflen) {
	    retval = GSS_S_DEFECTIVE_TOKEN;
	    goto cleanup;
	}
    } else {
	if (token->buffer.length != 16 + cksum_len) {
	    retval = GSS_S_DEFECTIVE_TOKEN;
	    goto cleanup;
	}
    }

    /* compute the checksum of the message */

    /* initialize the checksum */

    switch (signalg) {
    case SGN_ALG_DES_MAC_MD5:
    case SGN_ALG_MD2_5:
    case SGN_ALG_DES_MAC:
    case SGN_ALG_3:
	md5cksum.checksum_type = CKSUMTYPE_RSA_MD5;
	break;
    case SGN_ALG_HMAC_MD5:
	md5cksum.checksum_type = CKSUMTYPE_HMAC_MD5_ARCFOUR;
	break;
    case SGN_ALG_HMAC_SHA1_DES3_KD:
	md5cksum.checksum_type = CKSUMTYPE_HMAC_SHA1_DES3;
	break;
    default:
	abort();
    }

    code = krb5_c_checksum_length(context, md5cksum.checksum_type, &sumlen);
    if (code != 0) {
	retval = GSS_S_FAILURE;
	goto cleanup;
    }

    md5cksum.length = sumlen;

    switch (signalg) {
    case SGN_ALG_DES_MAC_MD5:
    case SGN_ALG_3:
	/* compute the checksum of the message */
	code = kg_checksum_iov(context, md5cksum.checksum_type, ctx->seq, ctx->enc,
			       sign_usage, iov_count, iov, &md5cksum);
	if (code != 0) {
	    retval = GSS_S_FAILURE;
	    goto cleanup;
	}

	code = kg_encrypt(context, ctx->seq, KG_USAGE_SEAL,
			  (g_OID_equal(ctx->mech_used, gss_mech_krb5_old) ?
			   ctx->seq->contents : NULL),
			  md5cksum.contents, md5cksum.contents, 16);
	if (code != 0) {
	    retval = GSS_S_FAILURE;
	    goto cleanup;
	}

	if (signalg == 0)
	    cksum.length = 8;
	else
	    cksum.length = 16;
	cksum.contents = md5cksum.contents + 16 - cksum.length;

	code = memcmp(cksum.contents, ptr + 14, cksum.length);
	break;
    case SGN_ALG_MD2_5: {
	unsigned char tmp[16];

	if (!ctx->seed_init &&
	    (code = kg_make_seed(context, ctx->subkey, ctx->seed))) {
	    *minor_status = code;
	    retval = GSS_S_FAILURE;
	}

	memcpy(tmp, (unsigned char *)token->buffer.value + 8, 16);
	memcpy((unsigned char *)token->buffer.value + 8, ctx->seed, sizeof(ctx->seed));

	code = kg_checksum_iov(context, md5cksum.checksum_type, ctx->seq, ctx->enc,
			       sign_usage, iov_count, iov, &md5cksum);

	memcpy((unsigned char *)token->buffer.value + 8, tmp, 16);

	if (code != 0) {
	    retval = GSS_S_FAILURE;
	    goto cleanup;
	}
	code = memcmp(cksum.contents, ptr + 14, cksum.length);
	break;
	}
    case SGN_ALG_HMAC_SHA1_DES3_KD:
    case SGN_ALG_HMAC_MD5:
	/* compute the checksum of the message */
	code = kg_checksum_iov(context, md5cksum.checksum_type, ctx->seq, ctx->enc,
			       sign_usage, iov_count, iov, &md5cksum);
	if (code != 0) {
	    retval = GSS_S_FAILURE;
	    goto cleanup;
	}
	code = memcmp(md5cksum.contents, ptr + 14, cksum_len);
	break;
    default:
	code = 0;
	retval = GSS_S_DEFECTIVE_TOKEN;
	goto cleanup;
	break;
    }

    if (code) {
	retval = GSS_S_BAD_SIG;
	goto cleanup;
    }

    if (conf_state != NULL)
	*conf_state = (sealalg != 0xFFFF);

    if (qop_state != NULL)
	*qop_state = GSS_C_QOP_DEFAULT;

    code = krb5_timeofday(context, &now);
    if (code != 0) {
	*minor_status = code;
	retval = GSS_S_FAILURE;
	goto cleanup;
    }

    if (now > ctx->endtime) {
	*minor_status = 0;
	retval = GSS_S_CONTEXT_EXPIRED;
	goto cleanup;
    }

    if ((ctx->initiate && direction != 0xff) ||
	(!ctx->initiate && direction != 0)) {
	*minor_status = G_BAD_DIRECTION;
	retval = GSS_S_BAD_SIG;
    }

    code = 0;
    retval = g_order_check(&ctx->seqstate, seqnum);

cleanup:
    kg_release_iov(iov_count, iov);
    krb5_free_checksum_contents(context, &md5cksum);

    *minor_status = code;

    return retval;
}

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

    token = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TOKEN);
    if (token == NULL) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    padding = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding == NULL) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

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

    input_length = token->buffer.length;

    if ((ctx->gss_flags & GSS_C_DCE_STYLE) == 0) {
	input_length += kg_iov_msglen(iov_count, iov, 0);
	input_length += padding->buffer.length;
    }

    code = g_verify_token_header(ctx->mech_used,
				 &bodysize, &ptr, toktype2,
				 input_length, !ctx->proto);
    if (code != 0) {
	*minor_status = code;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (ctx->proto == 0)
	code = kg_unseal_v1_iov(context, minor_status, ctx, iov_count, iov,
			        conf_state, qop_state, toktype);
    else
	;

    if (code != 0)
	save_error_info(*minor_status, context);

    return code;
}

