/* Copyright 2003 MIT.  All rights reserved. */
/* draft-ietf-krb-wg-gssapi-cfx-02 plus discussed changes */

#include <assert.h>
#include "k5-platform.h" 	/* for 64-bit support */
#include "k5-int.h"		/* for zap() */
#include "gssapiP_krb5.h"
#include <stdarg.h>

static int
rotate_left (void *ptr, size_t bufsiz, size_t rc)
{
    /* Optimize for receiving.  After some debugging is done, the MIT
       implementation won't do any rotates on sending, and while
       debugging, they'll be randomly chosen.

       Return 1 for success, 0 for failure (ENOMEM).  */
    void *tbuf;

    if (bufsiz == 0)
	return 1;
    if ((rc & 0xffff) != rc)
	abort();
    rc = rc % bufsiz;
    if (rc == 0)
	return 1;

    tbuf = malloc(rc);
    if (tbuf == 0)
	return 0;
    memcpy(tbuf, ptr, rc);
    memmove(ptr, (char *)ptr + rc, bufsiz - rc);
    memcpy((char *)ptr + bufsiz - rc, tbuf, rc);
    free(tbuf);
    return 1;
}

krb5_error_code
gss_krb5int_make_seal_token_v3 (krb5_context context,
				krb5_gss_ctx_id_rec *ctx,
				gss_buffer_t message,
				gss_buffer_t token,
				int conf_req_flag, int toktype)
{
    size_t bufsize = 16, cksumsize;
    unsigned char *outbuf = 0, *tmpbuf = 0;
    krb5_error_code err;
    int key_usage;
    unsigned char acceptor_flag;
    gss_buffer_desc *message2 = message;
    size_t rrc, ec;
    unsigned short tok_id;

    static const gss_buffer_desc empty_message = { 0, 0 };

    assert(toktype != KG_TOK_SEAL_MSG || ctx->enc != 0);
    assert(ctx->big_endian == 0);

    acceptor_flag = ctx->initiate ? 0 : 0x80;
    key_usage = (toktype == KG_TOK_WRAP_MSG
		 ? (ctx->initiate ? KG_USAGE_INITIATOR_SIGN : KG_USAGE_ACCEPTOR_SIGN)
		 : (ctx->initiate ? KG_USAGE_INITIATOR_SEAL : KG_USAGE_ACCEPTOR_SEAL));

    if (toktype == KG_TOK_WRAP_MSG && conf_req_flag) {
	krb5_data plain;
	krb5_enc_data cipher;
	size_t ec_max;

	/* 300: Adds some slop.  */
	if (SIZE_MAX - 300 < message->length)
	    return ENOMEM;
	ec_max = SIZE_MAX - message->length - 300;
	if (ec_max > 0xffff)
	    ec_max = 0xffff;
	/* For testing only.  For performance, always set ec = 0.  */
	ec = ec_max & rand();
	plain.length = message->length + 16 + ec;
	plain.data = malloc(message->length + 16 + ec);
	if (plain.data == NULL)
	    return ENOMEM;

	/* Get size of ciphertext.  */
	bufsize = 16 + krb5_encrypt_size (plain.length, ctx->enc->enctype);
	/* Allocate space for header plus encrypted data.  */
	outbuf = malloc(bufsize);
	if (outbuf == NULL) {
	    free(plain.data);
	    return ENOMEM;
	}

	/* TOK_ID */
	store_16_be(0x0504, outbuf);
	/* flags */
	/* no acceptor subkey stuff yet */
	outbuf[2] = acceptor_flag | (conf_req_flag ? 0x80 : 0);
	/* filler */
	outbuf[3] = 0xff;
	/* EC */
	store_16_be(ec, outbuf+4);
	/* RRC */
	store_16_be(0, outbuf+6);
	store_64_be(ctx->seq_send, outbuf+8);

	memcpy(plain.data, message->value, message->length);
	memset(plain.data + message->length, 'x', ec);
	memcpy(plain.data + message->length + ec, outbuf, 16);

	cipher.ciphertext.data = outbuf + 16;
	cipher.ciphertext.length = bufsize - 16;
	cipher.enctype = ctx->enc->enctype;
	err = krb5_c_encrypt(context, ctx->enc, key_usage, 0,
			     &plain, &cipher);
	zap(plain.data, plain.length);
	free(plain.data);
	plain.data = 0;
	if (err)
	    goto error;

	/* Now that we know we're returning a valid token....  */
	ctx->seq_send++;

	rrc = rand() & 0xffff;
	if (rotate_left(outbuf+16, bufsize-16,
			(bufsize-16) - (rrc % (bufsize - 16))))
	    store_16_be(rrc, outbuf+6);
	/* If the rotate fails, don't worry about it.  */
    } else if (toktype == KG_TOK_WRAP_MSG && !conf_req_flag) {
	krb5_data plain;
	krb5_checksum sum;

	/* Here, message is the application-supplied data; message2 is
	   what goes into the output token.  They may be the same, or
	   message2 may be empty (for MIC).  */

	tok_id = 0x0504;

    wrap_with_checksum:
	plain.length = message->length + 16;
	plain.data = malloc(message->length + 16);
	if (plain.data == NULL)
	    return ENOMEM;

	err = krb5_c_checksum_length (context, ctx->cksumtype, &cksumsize);
	if (err) {
	    free(plain.data);
	    plain.data = 0;
	    goto error;
	}
	if (cksumsize > 0xffff)
	    abort();

	bufsize = 16 + message2->length + cksumsize;
	outbuf = malloc(bufsize);
	if (outbuf == NULL) {
	    free(plain.data);
	    plain.data = 0;
	    err = ENOMEM;
	    goto error;
	}

	/* TOK_ID */
	store_16_be(tok_id, outbuf);
	/* flags */
	/* no acceptor subkey stuff yet */
	outbuf[2] = acceptor_flag | (conf_req_flag ? 0x80 : 0);
	/* filler */
	outbuf[3] = 0xff;
	if (toktype == KG_TOK_WRAP_MSG) {
	    /* Use 0 for checksum calculation, substitute
	       checksum length later.  */
	    /* EC */
	    store_16_be(0, outbuf+4);
	    /* RRC */
	    store_16_be(0, outbuf+6);
	} else {
	    /* MIC and DEL store 0xFF in EC and RRC.  */
	    store_16_be(0xffff, outbuf+4);
	    store_16_be(0xffff, outbuf+6);
	}
	store_64_be(ctx->seq_send, outbuf+8);

	/* For DEL_CTX, the message is empty, so it doesn't matter
	   which path we use.  The MIC path will probably change, for
	   security reasons.  */
	if (toktype != KG_TOK_MIC_MSG) {
	    memcpy(plain.data, outbuf, 16);
	    memcpy(plain.data + 16, message->value, message->length);
	} else {
	    memcpy(plain.data, message->value, message->length);
	    memcpy(plain.data+message->length, outbuf, 16);
	}
	sum.length = cksumsize;
	sum.contents = outbuf + 16;

	err = krb5_c_make_checksum(context, ctx->cksumtype, ctx->enc,
				   key_usage, &plain, &sum);

	ctx->seq_send++;

	rrc = rand() & 0xffff;
	/* If the rotate fails, don't worry about it.  */
	if (rotate_left(outbuf+16, bufsize-16,
			(bufsize-16) - (rrc % (bufsize - 16))))
	    store_16_be(rrc, outbuf+6);

	/* Fix up EC field.  */
	if (toktype == KG_TOK_WRAP_MSG)
	    store_16_be(cksumsize, outbuf+4);
    } else if (toktype == KG_TOK_MIC_MSG) {
	tok_id = 0x0404;
	message2 = &empty_message;
	goto wrap_with_checksum;
    } else if (toktype == KG_TOK_DEL_CTX) {
	tok_id = 0x0405;
	message = message2 = &empty_message;
	goto wrap_with_checksum;
    } else
	abort();

#if 0
    case KG_TOK_MIC_MSG:
	store_16_be(0x0404, outbuf);
    mic_del_common:
	{
	    krb5_checksum sum;
	    krb5_data plain;

	    outbuf[2] = acceptor_flag;
	    memset(outbuf+3, 0xff, 5);
	    store_64_be(ctx->seq, outbuf + 8);
	    sum.length = cksumsize;
	    sum.contents = outbuf + 16;
	    plain.length = 16 + message2->length;
	    tmpbuf = malloc(plain.length);
	    if (tmpbuf == NULL) {
		err = ENOMEM;
		goto error;
	    }
	    plain.data = tmpbuf;
	    memcpy(plain.data, outbuf, 16);
	    memcpy(plain.data + 16, message2->value, message2->length);
	    err = krb5_c_make_checksum(context, ctx->cksumtype, ctx->enc,
				       sign_usage, &plain, &sum);
	    if (err)
		goto error;
	}
	break;
#endif

    free(tmpbuf);
    token->value = outbuf;
    token->length = bufsize;
    return 0;

error:
    free(tmpbuf);
    free(outbuf);
    token->value = NULL;
    token->length = 0;
    return err;
}
