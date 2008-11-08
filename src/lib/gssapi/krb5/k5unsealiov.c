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
    OM_uint32 code;
    gss_iov_buffer_t header;
    gss_iov_buffer_t trailer;
    unsigned char *ptr;
    int sealalg;
    int signalg;
    krb5_checksum cksum;
    krb5_checksum md5cksum;
    krb5_timestamp now;
    size_t cksum_len = 0;
    size_t conflen = 0;
    int direction;
    krb5_ui_4 seqnum;
    OM_uint32 retval;
    size_t sumlen;
    krb5_keyusage sign_usage = KG_USAGE_SIGN;

    md5cksum.length = cksum.length = 0;
    md5cksum.contents = cksum.contents = NULL;

    header = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_HEADER);
    assert(header != NULL);

    trailer = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TRAILER);
    if (trailer != NULL && trailer->buffer.length != 0) {
	*minor_status = KRB5_BAD_MSIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    if (header->buffer.length < 16) {
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    ptr = ((unsigned char *)header->buffer.value) + 2; /* skip past TOK_ID */
   
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

    assert(ctx->big_endian == 0);

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
		code = kg_decrypt_iov(context, ctx->proto, 0, 0,
				      ctx->enc, KG_USAGE_SEAL, NULL,
				      iov_count, iov);
	    }
	    if (code != 0) {
		retval = GSS_S_FAILURE;
		goto cleanup;
	    }
	    conflen = kg_confounder_size(context, ctx->enc);

	    /*
	     * For GSS_C_DCE_STYLE, the caller manages the padding, because the
	     * pad length is in the RPC PDU. The value of the padding may be
	     * uninitialized. For normal GSS, the last bytes of the decrypted
	     * data contain the pad length. kg_fixup_padding_iov() will find
	     * this and fixup the last data IOV and padding IOV appropriately.
	     */
	    if ((ctx->gss_flags & GSS_C_DCE_STYLE) == 0) {
		retval = kg_fixup_padding_iov(&code, iov_count, iov);
		if (retval != GSS_S_COMPLETE)
		    goto cleanup;
	    }
	}
    }

    if (header->buffer.length != 16 + cksum_len + conflen) {
	retval = GSS_S_DEFECTIVE_TOKEN;
	goto cleanup;
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

    /* compute the checksum of the message */
    code = kg_make_checksum_iov_v1(context, md5cksum.checksum_type, ctx->seq, ctx->enc,
				   sign_usage, iov_count, iov, &md5cksum);
    if (code != 0) {
	retval = GSS_S_FAILURE;
	goto cleanup;
    }

    switch (signalg) {
    case SGN_ALG_DES_MAC_MD5:
    case SGN_ALG_3:
	code = kg_encrypt(context, ctx->seq, KG_USAGE_SEAL,
			  (g_OID_equal(ctx->mech_used, gss_mech_krb5_old) ?
			   ctx->seq->contents : NULL),
			  md5cksum.contents, md5cksum.contents, 16);
	if (code != 0) {
	    retval = GSS_S_FAILURE;
	    goto cleanup;
	}

	cksum.length = signalg == 0 ? 8 : 16;
	cksum.contents = md5cksum.contents + 16 - cksum.length;

	code = memcmp(cksum.contents, ptr + 14, cksum.length);
	break;
    case SGN_ALG_HMAC_SHA1_DES3_KD:
    case SGN_ALG_HMAC_MD5:
	code = memcmp(md5cksum.contents, ptr + 14, cksum_len);
	break;
    default:
	code = 0;
	retval = GSS_S_DEFECTIVE_TOKEN;
	goto cleanup;
	break;
    }

    if (code != 0) {
	code = 0;
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

/*
 * Caller must provide TOKEN | DATA | PADDING | TRAILER
 */
static OM_uint32
kg_unseal_iov_token(OM_uint32 *minor_status,
		    krb5_gss_ctx_id_rec *ctx,
		    int *conf_state,
		    gss_qop_t *qop_state,
		    size_t iov_count,
		    gss_iov_buffer_desc *iov,
		    int toktype,
		    int toktype2)
{
    krb5_error_code code;
    krb5_context context;
    unsigned char *ptr;
    gss_iov_buffer_t header;
    gss_iov_buffer_t padding;
    gss_iov_buffer_t trailer;
    size_t input_length;
    unsigned int bodysize;

    header = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_HEADER);
    if (header == NULL) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    padding = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding == NULL) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    trailer = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TRAILER);

    ptr = (unsigned char *)header->buffer.value;
    input_length = header->buffer.length;

    if ((ctx->gss_flags & GSS_C_DCE_STYLE) == 0) {
	size_t data_length, assoc_data_length;

	kg_iov_msglen(iov_count, iov, &data_length, &assoc_data_length);

	input_length += data_length;

	if (padding != NULL)
	    input_length += padding->buffer.length;

	if (trailer != NULL)
	    input_length += trailer->buffer.length;
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
	code = gss_krb5int_unseal_v3_iov(context, minor_status, ctx, iov_count, iov,
					 conf_state, qop_state, toktype);

    if (code != 0)
	save_error_info(*minor_status, context);

    return code;
}

/*
 * Split a STREAM into TOKEN | DATA | PADDING | TRAILER
 */
static OM_uint32
kg_tokenize_stream_iov(OM_uint32 *minor_status,
		       krb5_gss_ctx_id_rec *ctx,
		       gss_iov_buffer_t stream,
		       gss_iov_buffer_t data,
		       gss_iov_buffer_desc iov[4],
		       int toktype2)
{
    unsigned char *ptr;
    unsigned int bodysize;
    krb5_error_code code;
    krb5_context context;
    int conf_req_flag;
    size_t data_length;

    assert(stream != NULL);
    assert(data != NULL);

    if (ctx->gss_flags & GSS_C_DCE_STYLE) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    ptr = (unsigned char *)stream->buffer.value;

    code = g_verify_token_header(ctx->mech_used,
				 &bodysize, &ptr, toktype2,
				 stream->buffer.length,
				 !ctx->proto);
    if (code != 0 || stream->buffer.length < 16) {
	*minor_status = code;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    iov[0].buffer.value = stream->buffer.value;
    iov[0].buffer.length = 16;

    if (ctx->proto == 1) {
	size_t ec, rrc;
	krb5_enctype enctype = ctx->enc->enctype;
	size_t k5_headerlen = 0;
	size_t k5_trailerlen = 0;

	conf_req_flag = ((ptr[0] & FLAG_WRAP_CONFIDENTIAL) != 0);
	ec = load_16_be(ptr + 2);
	rrc = load_16_be(ptr + 4);

	if (rrc != 0) {
	    code = gss_krb5int_rotate_left((unsigned char *)stream->buffer.value + 16,
					   stream->buffer.length - 16, rrc);;
	    if (code != 0) {
		*minor_status = code;
		return GSS_S_FAILURE;
	    }
	    store_16_be(0, ptr + 4); /* set RRC to zero */
	}

	if (conf_req_flag) {
	    code = krb5_c_crypto_length(context, enctype, KRB5_CRYPTO_TYPE_HEADER, &k5_headerlen);
	    if (code != 0) {
		*minor_status = code;
		return GSS_S_FAILURE;
	    }
	    iov[0].buffer.length += k5_headerlen;
	}

	code = krb5_c_crypto_length(context, enctype,
				    conf_req_flag ? KRB5_CRYPTO_TYPE_TRAILER : KRB5_CRYPTO_TYPE_CHECKSUM,
				    &k5_trailerlen);
	if (code != 0) {
	    *minor_status = code;
	    return GSS_S_FAILURE;
	}

	/* setup trailer */
	iov[3].buffer.length = conf_req_flag ? 16 : 0 /* E(Header) */ + k5_trailerlen;
	iov[3].buffer.value = (unsigned char *)stream->buffer.value + stream->buffer.length - iov[3].buffer.length;

	/* setup padding */
	iov[2].buffer.length = ec;
	iov[2].buffer.value = (unsigned char *)stream->buffer.value + stream->buffer.length - iov[3].buffer.length - ec;
    } else {
	conf_req_flag = (ptr[2] != 0xFF && ptr[3] != 0xFF);

	iov[0].buffer.length += ctx->cksum_size;
  
	if (conf_req_flag)
	    iov[0].buffer.length += kg_confounder_size(context, ctx->enc);

	/* no trailer */
	iov[3].buffer.length = 0;
	iov[3].buffer.value = NULL;

	/*
	 * we can't set the padding accurately until decryption;
	 * kg_fixup_padding_iov() will take care of this
	 */
	iov[2].buffer.length = 1;
	iov[2].buffer.value = (unsigned char *)stream->buffer.value + stream->buffer.length - 1;
    }

    /* IOV: -----------0-------------+---1---+--2--+-------------3------------*/
    /* Old: GSS-Header | Conf        | Data  | Pad |                          */
    /* CFX: GSS-Header | Kerb-Header | Data  | EC  | E(Header) | Kerb-Trailer */

    /* Add 2 to bodysize for TOK_ID */
    if (2 + bodysize < iov[0].buffer.length + iov[2].buffer.length + iov[3].buffer.length) {
	*minor_status = KRB5_BAD_MSIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    /* setup data */
    data_length = stream->buffer.length - iov[0].buffer.length - iov[2].buffer.length - iov[3].buffer.length;

    if (data->flags & GSS_IOV_BUFFER_FLAG_ALLOCATE) {
	iov[1].buffer.value = xmalloc(data_length);
	if (iov[1].buffer.value == NULL) {
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	memcpy(iov[1].buffer.value, (unsigned char *)stream->buffer.value + iov[0].buffer.length, data_length);
	iov[1].flags |= GSS_IOV_BUFFER_FLAG_ALLOCATED;
    } else {
	iov[1].buffer.value = (unsigned char *)stream->buffer.value + iov[0].buffer.length;
    }

    iov[1].buffer.length = data_length;

    *minor_status = 0;

    return GSS_S_COMPLETE;
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
    gss_iov_buffer_desc tokenized_iov[4];
    gss_iov_buffer_t stream, data;
    OM_uint32 code;
    int toktype2;

    if (!kg_validate_ctx_id(context_handle)) {
	*minor_status = G_VALIDATE_FAILED;
	return GSS_S_NO_CONTEXT;
    }

    ctx = (krb5_gss_ctx_id_rec *)context_handle;
    if (!ctx->established) {
	*minor_status = KG_CTX_INCOMPLETE;
	return GSS_S_NO_CONTEXT;
    }

    toktype2 = kg_map_toktype(ctx->proto, toktype);

    assert(toktype2 == KG_TOK_WRAP_MSG);

    stream = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_STREAM);
    if (stream != NULL) {
	data = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_DATA);
	if (data == NULL) {
	    *minor_status = EINVAL;
	    return GSS_S_FAILURE;
	}

	memset(&tokenized_iov[0], 0, sizeof(tokenized_iov));

	code = kg_tokenize_stream_iov(minor_status, ctx, stream, data, tokenized_iov, toktype2);
	if (code != GSS_S_COMPLETE)
	    return code;
    } else
	data = NULL;

    code = kg_unseal_iov_token(minor_status, ctx, conf_state, qop_state,
			       stream != NULL ? 4 : iov_count,
			       stream != NULL ? tokenized_iov : iov,
			       toktype, toktype2);

    if (data != NULL)
	*data = tokenized_iov[1];

    return code;
}

