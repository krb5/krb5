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

static const gss_buffer_desc empty_message = { 0, 0 };

#define FLAG_SENDER_IS_ACCEPTOR	0x80
#define FLAG_WRAP_CONFIDENTIAL	0x40
#define FLAG_ACCEPTOR_SUBKEY	0x20

void
_log_block(const char *file, int line, const char *label,
	   void *vptr, size_t len)
{
    char b[8 * 4 + 4];
    int i, j;
    if (strrchr(file, '/'))
	file = 1 + strrchr(file, '/');
#if 0
    _log("%s:%d: %s: %d at %p\n", file, line, label, len, vptr);
    for (i = 0; i < (len + 7) / 8; i++) {
	unsigned char *base = (i * 8) + (unsigned char *)vptr;
	b[0] = 0;
	for (j = 0; j < 8 && j < (len - i * 8); j++)
	    sprintf(b+strlen(b), " %02x", base[j]);
	_log("\t\t%04x/@%p:%s\n", 8 * i, base, b);
    }
#else
    _log("%s:%d: %s: %d at %p [omitted]\n", file, line, label, len, vptr);
#endif
}

krb5_error_code
gss_krb5int_make_seal_token_v3 (krb5_context context,
				krb5_gss_ctx_id_rec *ctx,
				const gss_buffer_desc * message,
				gss_buffer_t token,
				int conf_req_flag, int toktype)
{
    size_t bufsize = 16;
    unsigned char *outbuf = 0;
    krb5_error_code err;
    int key_usage;
    unsigned char acceptor_flag;
    const gss_buffer_desc *message2 = message;
    size_t rrc, ec;
    unsigned short tok_id;
    krb5_checksum sum;

    assert(toktype != KG_TOK_SEAL_MSG || ctx->enc != 0);
    assert(ctx->big_endian == 0);

    acceptor_flag = ctx->initiate ? 0 : 0x80;
    key_usage = (toktype == KG_TOK_WRAP_MSG
		 ? (ctx->initiate
		    ? KG_USAGE_INITIATOR_SIGN
		    : KG_USAGE_ACCEPTOR_SIGN)
		 : (ctx->initiate
		    ? KG_USAGE_INITIATOR_SEAL
		    : KG_USAGE_ACCEPTOR_SEAL));

#define SFILE (strrchr(__FILE__,'/') ? 1+strrchr(__FILE__,'/') : __FILE__)

    _log("%s:%d: wrap input token: %d @%p toktype=0x%x\n", SFILE, __LINE__,
	 message->length, message->value, toktype);

    {
	static int initialized = 0;
	if (!initialized) {
	    srand(time(0));
	    initialized = 1;
	}
    }

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
	_log("%s:%d: ec=%d\n", SFILE, __LINE__, ec);
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
	outbuf[2] = acceptor_flag | (conf_req_flag ? 0x40 : 0);
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
	_log("%s:%d: just encrypted:\n"
	     "\t(key=%d/%02x%02x..., usage=%d, plain.length=%d,\n"
	     "\t ciphertext=%d/%02x%02x...)\n",
	     SFILE, __LINE__, ctx->enc->enctype,
	     ctx->enc->contents[0], ctx->enc->contents[1],
	     key_usage, plain.length,
	     cipher.ciphertext.length,
	     0xff & cipher.ciphertext.data[0],
	     0xff & cipher.ciphertext.data[1]);

	/* Now that we know we're returning a valid token....  */
	ctx->seq_send++;

	rrc = rand() & 0xffff;
	if (rotate_left(outbuf+16, bufsize-16,
			(bufsize-16) - (rrc % (bufsize - 16))))
	    store_16_be(rrc, outbuf+6);
	/* If the rotate fails, don't worry about it.  */
    } else if (toktype == KG_TOK_WRAP_MSG && !conf_req_flag) {
	krb5_data plain;

	/* Here, message is the application-supplied data; message2 is
	   what goes into the output token.  They may be the same, or
	   message2 may be empty (for MIC).  */

	tok_id = 0x0504;

    wrap_with_checksum:
	plain.length = message->length + 16;
	plain.data = malloc(message->length + 16);
	if (plain.data == NULL)
	    return ENOMEM;

	_log("%s:%d: cksumtype=%d\n", SFILE, __LINE__, ctx->cksumtype);
	if (ctx->cksum_size > 0xffff)
	    abort();

	bufsize = 16 + message2->length + ctx->cksum_size;
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

	memcpy(plain.data, message->value, message->length);
	memcpy(plain.data + message->length, outbuf, 16);

	/* Fill in the output token -- data contents, if any, and
	   space for the checksum.  */
	if (message2->length)
	    memcpy(outbuf + 16, message2->value, message2->length);

	sum.contents = outbuf + 16 + message2->length;
	sum.length = ctx->cksum_size;
	_log("%s:%d: checksum @%p outbuf @%p offset %d\n", SFILE, __LINE__,
	     sum.contents, outbuf, sum.contents - outbuf);
	_log_block(SFILE, __LINE__, "checksum input",
		   plain.data, plain.length);

	err = krb5_c_make_checksum(context, ctx->cksumtype, ctx->enc,
				   key_usage, &plain, &sum);
	zap(plain.data, plain.length);
	free(plain.data);
	plain.data = 0;
	if (err) {
	    zap(outbuf,bufsize);
	    free(outbuf);
	    goto error;
	}
	_log_block(SFILE, __LINE__, "checksum result",
		   sum.contents, sum.length);
	if (sum.length != ctx->cksum_size)
	    abort();
	memcpy(outbuf + 16 + message2->length, sum.contents, ctx->cksum_size);
	krb5_free_checksum_contents(context, &sum);
	sum.contents = 0;
	/* Now that we know we're actually generating the token...  */
	ctx->seq_send++;

	if (toktype == KG_TOK_WRAP_MSG) {
	    rrc = rand() & 0xffff;
	    /* If the rotate fails, don't worry about it.  */
	    if (rotate_left(outbuf+16, bufsize-16,
			    (bufsize-16) - (rrc % (bufsize - 16))))
		store_16_be(rrc, outbuf+6);
	    /* Fix up EC field.  */
	    store_16_be(ctx->cksum_size, outbuf+4);
	} else {
	    store_16_be(0xffff, outbuf+6);
	}
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

    token->value = outbuf;
    token->length = bufsize;
    _log_block(SFILE, __LINE__, "output token", token->value, token->length);
    return 0;

error:
    free(outbuf);
    token->value = NULL;
    token->length = 0;
    return err;
}

/* message_buffer is an input if SIGN, output if SEAL, and ignored if DEL_CTX
   conf_state is only valid if SEAL. */

OM_uint32
gss_krb5int_unseal_token_v3(krb5_context *contextptr,
			    OM_uint32 *minor_status,
			    krb5_gss_ctx_id_rec *ctx,
			    unsigned char *ptr, int bodysize,
			    gss_buffer_t message_buffer,
			    int *conf_state, int *qop_state, int toktype)
{
    krb5_context context = *contextptr;
    krb5_data plain;
    gssint_uint64 seqnum;
    size_t ec, rrc;
    int key_usage;
    unsigned char acceptor_flag;
    krb5_checksum sum;
    krb5_error_code err;
    krb5_boolean valid;

    assert(toktype != KG_TOK_SEAL_MSG || ctx->enc != 0);
    assert(ctx->big_endian == 0);
    assert(ctx->proto == 1);

    if (qop_state)
	*qop_state = GSS_C_QOP_DEFAULT;

    acceptor_flag = ctx->initiate ? FLAG_SENDER_IS_ACCEPTOR : 0;
    key_usage = (toktype == KG_TOK_WRAP_MSG
		 ? (!ctx->initiate
		    ? KG_USAGE_INITIATOR_SIGN
		    : KG_USAGE_ACCEPTOR_SIGN)
		 : (!ctx->initiate
		    ? KG_USAGE_INITIATOR_SEAL
		    : KG_USAGE_ACCEPTOR_SEAL));

#define LOG()		_log("%s:%d: here\n", SFILE, __LINE__)
#define DEFECTIVE	do{LOG();goto defective;}while(0)

    _log ("%s:%d: bodysize %d ptr @%p: %02x %02x\n", SFILE, __LINE__,
	  bodysize, ptr, ptr[0], ptr[1]);

    /* Oops.  I wrote this code assuming ptr would be at the start of
       the token header.  */
    ptr -= 2;
    bodysize += 2;

    _log_block(SFILE, __LINE__, "input token", ptr, bodysize);

    if (bodysize < 16) {
	LOG();
    defective:
	*minor_status = 0;
	return GSS_S_DEFECTIVE_TOKEN;
    }
    LOG();
    if ((ptr[2] & FLAG_SENDER_IS_ACCEPTOR) != acceptor_flag) {
	*minor_status = G_BAD_DIRECTION;
	return GSS_S_BAD_SIG;
    }
    LOG();
    if (toktype == KG_TOK_WRAP_MSG) {
	if (load_16_be(ptr) != 0x0504)
	    DEFECTIVE;
	if (ptr[2] & ~0xe0)
	    DEFECTIVE;
	if (ptr[3] != 0xff)
	    DEFECTIVE;
	ec = load_16_be(ptr+4);
	rrc = load_16_be(ptr+6);
	seqnum = load_64_be(ptr+8);
	if (!rotate_left(ptr+16, bodysize-16, rrc)) {
	no_mem:
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}
	if (ptr[2] & FLAG_WRAP_CONFIDENTIAL) {
	    /* confidentiality */
	    krb5_enc_data cipher;
	    unsigned char *althdr;

    LOG();
	    if (conf_state)
		*conf_state = 1;
	    /* Do we have no decrypt_size function?

	       For all current cryptosystems, the ciphertext size will
	       be larger than the plaintext size.  */
	    cipher.enctype = ctx->enc->enctype;
	    cipher.ciphertext.length = bodysize - 16;
	    cipher.ciphertext.data = ptr + 16;
	    plain.length = bodysize - 16;
	    plain.data = malloc(plain.length);
	    if (plain.data == NULL)
		goto no_mem;
	    _log("%s:%d: about to decrypt:\n"
		 "\t(key=%d/%02x%02x..., usage=%d, ciphertext=%d/%02x%02x...)\n",
		 SFILE, __LINE__, ctx->enc->enctype,
		 ctx->enc->contents[0], ctx->enc->contents[1],
		 key_usage,
		 cipher.ciphertext.length,
		 0xff & cipher.ciphertext.data[0],
		 0xff & cipher.ciphertext.data[1]);
	    err = krb5_c_decrypt(context, ctx->enc, key_usage, 0,
				 &cipher, &plain);
	    if (err) {
		free(plain.data);
		_log("%s:%d: error %ld/%s\n", SFILE, __LINE__,
		     (long) err, error_message(err));
		goto error;
	    }
	    /* Don't use bodysize here!  Use the fact that
	       cipher.ciphertext.length has been adjusted to the
	       correct length.  */
    LOG();
	    althdr = plain.data + plain.length - 16;
	    if (load_16_be(althdr) != 0x0504
		|| althdr[2] != ptr[2]
		|| althdr[3] != ptr[3]
		|| memcmp(althdr+8, ptr+8, 8))
		DEFECTIVE;
	    message_buffer->value = plain.data;
	    _log("%s:%d: plaintext len=%d, ec=%d\n", SFILE, __LINE__,
		 plain.length, ec);
	    message_buffer->length = plain.length - ec - 16;
	    _log("%s:%d: decrypted token %d @%p\n", SFILE, __LINE__,
		 message_buffer->length, message_buffer->value);
	} else {
	    /* no confidentiality */
    LOG();
	    if (conf_state)
		*conf_state = 0;
	    if (ec + 16 < ec)
		/* overflow check */
		DEFECTIVE;
    LOG();
	    if (ec + 16 > bodysize)
		DEFECTIVE;
    LOG();
	    /* We have: header | msg | cksum.
	       We need cksum(msg | header).
	       Rotate the first two.  */
	    store_16_be(0, ptr+4);
	    store_16_be(0, ptr+6);
	    plain.length = bodysize-ec;
	    plain.data = ptr;
	    if (!rotate_left(ptr, bodysize-ec, 16))
		goto no_mem;
	    sum.length = ec;
	    if (sum.length != ctx->cksum_size) {
		*minor_status = 0;
    LOG();
		return GSS_S_BAD_SIG;
	    }
	    sum.contents = ptr+bodysize-ec;
	    sum.checksum_type = ctx->cksumtype;
	    _log_block(SFILE, __LINE__, "checksum data input",
		       plain.data, plain.length);
	    _log_block(SFILE, __LINE__, "checksum to test",
		       sum.contents, sum.length);
	    err = krb5_c_verify_checksum(context, ctx->enc, key_usage,
					 &plain, &sum, &valid);
	    if (err)
		goto error;
	    _log("%s:%d: valid=%d\n", SFILE, __LINE__, valid);
	    if (!valid) {
    LOG();
		*minor_status = 0;
		return GSS_S_BAD_SIG;
	    }
	    message_buffer->length = plain.length - 16;
	    message_buffer->value = malloc(message_buffer->length);
	    if (message_buffer->value == NULL)
		goto no_mem;
	    memcpy(message_buffer->value, plain.data, message_buffer->length);
	}
    LOG();
	err = g_order_check(&ctx->seqstate, seqnum);
	*minor_status = 0;
	_log("%s:%d: g_order_check => %d/%s, unseal %s\n", SFILE, __LINE__,
	     err, err ? error_message(err) : "No error",
	     err ? "failed" : "passed");
	return err;
    } else if (toktype == KG_TOK_MIC_MSG) {
	/* wrap token, no confidentiality */
    LOG();
	if (load_16_be(ptr) != 0x0404)
	    DEFECTIVE;
    LOG();
    verify_mic_1:
    LOG();
	if (ptr[2] & ~0xe0)
	    DEFECTIVE;
    LOG();
	if (ptr[3] != 0xff)
	    DEFECTIVE;
	_log("%s:%d: at ptr+4 %p: %02x %02x %02x %02x\n", SFILE, __LINE__,
	     ptr+4, ptr[4], ptr[5], ptr[6], ptr[7]);
	if (load_32_be(ptr+4) != 0xffffffffL)
	    DEFECTIVE;
    LOG();
	seqnum = load_64_be(ptr+8);
	plain.length = message_buffer->length + 16;
	plain.data = malloc(plain.length);
	if (plain.data == NULL)
	    goto no_mem;
	if (message_buffer->length)
	    memcpy(plain.data, message_buffer->value, message_buffer->length);
	memcpy(plain.data + message_buffer->length, ptr, 16);
	sum.length = bodysize - 16;
	sum.contents = ptr + 16;
	sum.checksum_type = ctx->cksumtype;
	_log("%s:%d: sum.length = %d\n", SFILE, __LINE__, sum.length);
	    _log_block(SFILE, __LINE__, "checksum data input",
		       plain.data, plain.length);
	    _log_block(SFILE, __LINE__, "checksum to test",
		       sum.contents, sum.length);
	err = krb5_c_verify_checksum(context, ctx->enc, key_usage,
				     &plain, &sum, &valid);
	if (err) {
	error:
	    free(plain.data);
    LOG();
	    *minor_status = err;
	    return GSS_S_BAD_SIG; /* XXX */
	}
    LOG();
	if (!valid) {
	    free(plain.data);
	    *minor_status = 0;
    LOG();
	    return GSS_S_BAD_SIG;
	}
    LOG();
	err = g_order_check(&ctx->seqstate, seqnum);
	*minor_status = 0;
	return err;
    } else if (toktype == KG_TOK_DEL_CTX) {
    LOG();
	if (load_16_be(ptr) != 0x0405)
	    DEFECTIVE;
    LOG();
	message_buffer = &empty_message;
	goto verify_mic_1;
    } else {
    LOG();
	DEFECTIVE;
    }
}
