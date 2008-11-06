/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * lib/gssapi/krb5/k5sealv3iov.c
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

krb5_error_code
gss_krb5int_make_seal_token_v3_iov(krb5_context context,
				   krb5_gss_ctx_id_rec *ctx,
				   int conf_req_flag,
				   int *conf_state,
				   size_t iov_count,
				   gss_iov_buffer_desc *iov,
				   int toktype)
{
    krb5_error_code code;
    gss_iov_buffer_t header;
    gss_iov_buffer_t trailer;
    gss_iov_buffer_t padding = NULL;
    unsigned char acceptor_flag;
    unsigned short tok_id;
    unsigned char *outbuf = NULL;
    int key_usage, dce_style;
    size_t rrc, ec;
    size_t data_length, assoc_data_length;
    size_t headerlen;
    krb5_keyblock *key;

    assert(toktype != KG_TOK_SEAL_MSG || ctx->enc != 0);
    assert(ctx->big_endian == 0);

    acceptor_flag = ctx->initiate ? 0 : FLAG_SENDER_IS_ACCEPTOR;
    key_usage = (toktype == KG_TOK_WRAP_MSG
		 ? (ctx->initiate
		    ? KG_USAGE_INITIATOR_SEAL
		    : KG_USAGE_ACCEPTOR_SEAL)
		 : (ctx->initiate
		    ? KG_USAGE_INITIATOR_SIGN
		    : KG_USAGE_ACCEPTOR_SIGN));
    if (ctx->have_acceptor_subkey) {
	key = ctx->acceptor_subkey;
    } else {
	key = ctx->enc;
    }

    header = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_HEADER);
    if (header == NULL)
	return EINVAL;

    if (toktype == KG_TOK_WRAP_MSG && conf_req_flag) {
	padding = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_PADDING);
	if (padding == NULL)
	    return EINVAL;
    }

    dce_style = ((ctx->gss_flags & GSS_C_DCE_STYLE) != 0);

    trailer = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TRAILER);
    if (trailer != NULL)
	trailer->buffer.length = 0;
    else if (!dce_style)
	return EINVAL;

    kg_iov_msglen(iov_count, iov, &data_length, &assoc_data_length);

    outbuf = (unsigned char *)header->buffer.value;

    if (toktype == KG_TOK_WRAP_MSG && conf_req_flag) {
	size_t k5_headerlen, k5_padlen, k5_trailerlen;

	code = krb5_c_crypto_length(context, key->enctype, KRB5_CRYPTO_TYPE_HEADER, &k5_headerlen);
	if (code != 0)
	    goto cleanup;

	if (dce_style) {
	    k5_padlen = k5_headerlen; /* assume this to be the block size */
	} else {
	    code = krb5_c_crypto_length(context, key->enctype, KRB5_CRYPTO_TYPE_PADDING, &k5_padlen);
	    if (code != 0)
		goto cleanup;
	}

	code = krb5_c_crypto_length(context, key->enctype, KRB5_CRYPTO_TYPE_TRAILER, &k5_trailerlen);
	if (code != 0)
	    goto cleanup;

	headerlen = 16 /* Header */ + k5_headerlen;
	if (!dce_style)
	    headerlen += 16 /* E(Header) */ + k5_trailerlen;

	if ((header->buffer.length < headerlen) ||
	    (!dce_style && trailer->buffer.length < 16 /* E(Header) */ + k5_trailerlen)) {
	    code = ERANGE;
	    goto cleanup;
	}

	if (trailer != NULL) {
	    trailer->buffer.length = dce_style ? 0 : 16 /* E(Header) */ + k5_trailerlen;
	}

	ec = k5_padlen - ((16 + data_length - assoc_data_length) % k5_padlen);
	if (padding->buffer.length < ec) {
	    code = ERANGE;
	    goto cleanup;
	}
	padding->buffer.length = ec;
	memset(padding->buffer.value, 'x', ec);

	if (dce_style)
	    rrc = 16 /* E(Header) */ + k5_trailerlen;
	else
	    rrc = 0;

	/* TOK_ID */
	store_16_be(0x0504, outbuf);
	/* flags */
	outbuf[2] = (acceptor_flag
		     | (conf_req_flag ? FLAG_WRAP_CONFIDENTIAL : 0)
		     | (ctx->have_acceptor_subkey ? FLAG_ACCEPTOR_SUBKEY : 0));
	/* filler */
	outbuf[3] = 0xFF;
	/* EC */
	store_16_be(ec, outbuf + 4);
	/* RRC */
	store_16_be(rrc, outbuf + 6);
	store_64_be(ctx->seq_send, outbuf + 8);

	code = kg_encrypt_iov(context, ctx->proto, rrc, key, key_usage, 0, iov_count, iov);
	if (code != 0)
	    goto cleanup;

	ctx->seq_send++;
    } else if (toktype == KG_TOK_WRAP_MSG && !conf_req_flag) {
	assert(ctx->cksum_size <= 0xFFFF);

	tok_id = 0x0504;

    wrap_with_checksum:

	if (dce_style)
	    rrc = ctx->cksum_size;
	else
	    rrc = 0;

	/* TOK_ID */
	store_16_be(tok_id, outbuf);
	/* flags */
	outbuf[2] = (acceptor_flag
		     | (ctx->have_acceptor_subkey ? FLAG_ACCEPTOR_SUBKEY : 0));
	/* filler */
	outbuf[3] = 0xFF;
	if (toktype == KG_TOK_WRAP_MSG) {
	    /* Use 0 for checksum calculation, substitute
	     * checksum length later.
	     */
	    /* EC */
	    store_16_be(0, outbuf + 4);
	    /* RRC */
	    store_16_be(0, outbuf + 6);
	} else {
	    /* MIC and DEL store 0xFF in EC and RRC */
	    store_16_be(0xFFFF, outbuf + 4);
	    store_16_be(0xFFFF, outbuf + 6);
	}
	store_64_be(ctx->seq_send, outbuf + 8);

	code = kg_checksum_iov_v3(context, ctx->cksumtype,
				  rrc, key, key_usage,
				  iov_count, iov);
	if (code != 0)
	    goto cleanup;

	ctx->seq_send++;

	if (toktype == KG_TOK_WRAP_MSG) {
	    /* Fix up EC field */
	    store_16_be(ctx->cksum_size, outbuf + 4);
	    /* Fix up RRC field */
	    store_16_be(rrc, outbuf + 6);
	}
    } else if (toktype == KG_TOK_MIC_MSG) {
	tok_id = 0x0404;
	goto wrap_with_checksum;
    } else if (toktype == KG_TOK_DEL_CTX) {
	tok_id = 0x0405;
	goto wrap_with_checksum;
    } else {
	abort();
    }

    code = 0;

cleanup:
    return code;
}

