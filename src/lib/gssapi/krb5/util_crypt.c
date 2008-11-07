/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * Copyright2001 by the Massachusetts Institute of Technology.
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "gssapiP_krb5.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

int
kg_confounder_size(context, key)
    krb5_context context;
    krb5_keyblock *key;
{
    krb5_error_code code;
    size_t blocksize;
    /* We special case rc4*/
    if (key->enctype == ENCTYPE_ARCFOUR_HMAC)
        return 8;
    code = krb5_c_block_size(context, key->enctype, &blocksize);
    if (code)
        return(-1); /* XXX */

    return(blocksize);
}

krb5_error_code
kg_make_confounder(context, key, buf)
    krb5_context context;
    krb5_keyblock *key;
    unsigned char *buf;
{
    krb5_error_code code;
    size_t blocksize;
    krb5_data lrandom;

    code = krb5_c_block_size(context, key->enctype, &blocksize);
    if (code)
        return(code);

    lrandom.length = blocksize;
    lrandom.data = (char *)buf;

    return(krb5_c_random_make_octets(context, &lrandom));
}

krb5_error_code
kg_encrypt(context, key, usage, iv, in, out, length)
    krb5_context context;
    krb5_keyblock *key;
    int usage;
    krb5_pointer iv;
    krb5_const_pointer in;
    krb5_pointer out;
    unsigned int length;
{
    krb5_error_code code;
    size_t blocksize;
    krb5_data ivd, *pivd, inputd;
    krb5_enc_data outputd;

    if (iv) {
        code = krb5_c_block_size(context, key->enctype, &blocksize);
        if (code)
            return(code);

        ivd.length = blocksize;
        ivd.data = malloc(ivd.length);
        if (ivd.data == NULL)
            return ENOMEM;
        memcpy(ivd.data, iv, ivd.length);
        pivd = &ivd;
    } else {
        pivd = NULL;
    }

    inputd.length = length;
    inputd.data = (char *)in;

    outputd.ciphertext.length = length;
    outputd.ciphertext.data = out;

    code = krb5_c_encrypt(context, key, usage, pivd, &inputd, &outputd);
    if (pivd != NULL)
        free(pivd->data);
    return code;
}

/* length is the length of the cleartext. */

krb5_error_code
kg_decrypt(context, key, usage, iv, in, out, length)
    krb5_context context;
    krb5_keyblock *key;
    int usage;
    krb5_pointer iv;
    krb5_const_pointer in;
    krb5_pointer out;
    unsigned int length;
{
    krb5_error_code code;
    size_t blocksize;
    krb5_data ivd, *pivd, outputd;
    krb5_enc_data inputd;

    if (iv) {
        code = krb5_c_block_size(context, key->enctype, &blocksize);
        if (code)
            return(code);

        ivd.length = blocksize;
        ivd.data = malloc(ivd.length);
        if (ivd.data == NULL)
            return ENOMEM;
        memcpy(ivd.data, iv, ivd.length);
        pivd = &ivd;
    } else {
        pivd = NULL;
    }

    inputd.enctype = ENCTYPE_UNKNOWN;
    inputd.ciphertext.length = length;
    inputd.ciphertext.data = (char *)in;

    outputd.length = length;
    outputd.data = out;

    code = krb5_c_decrypt(context, key, usage, pivd, &inputd, &outputd);
    if (pivd != NULL)
        free(pivd->data);
    return code;
}

krb5_error_code
kg_arcfour_docrypt (const krb5_keyblock *longterm_key , int ms_usage,
                    const unsigned char *kd_data, size_t kd_data_len,
                    const unsigned char *input_buf, size_t input_len,
                    unsigned char *output_buf)
{
    krb5_error_code code;
    krb5_data input, output;
    krb5int_access kaccess;
    krb5_keyblock seq_enc_key, usage_key;
    unsigned char t[4];

    usage_key.length = longterm_key->length;
    usage_key.contents = malloc(usage_key.length);
    if (usage_key.contents == NULL)
        return (ENOMEM);
    seq_enc_key.length = longterm_key->length;
    seq_enc_key.contents = malloc(seq_enc_key.length);
    if (seq_enc_key.contents == NULL) {
        free ((void *) usage_key.contents);
        return (ENOMEM);
    }
    code = krb5int_accessor (&kaccess, KRB5INT_ACCESS_VERSION);
    if (code)
        goto cleanup_arcfour;

    t[0] = ms_usage &0xff;
    t[1] = (ms_usage>>8) & 0xff;
    t[2] = (ms_usage>>16) & 0xff;
    t[3] = (ms_usage>>24) & 0xff;
    input.data = (void *) &t;
    input.length = 4;
    output.data = (void *) usage_key.contents;
    output.length = usage_key.length;
    code = (*kaccess.krb5_hmac) (kaccess.md5_hash_provider,
                                 longterm_key, 1, &input, &output);
    if (code)
        goto cleanup_arcfour;

    input.data = ( void *) kd_data;
    input.length = kd_data_len;
    output.data = (void *) seq_enc_key.contents;
    code = (*kaccess.krb5_hmac) (kaccess.md5_hash_provider,
                                 &usage_key, 1, &input, &output);
    if (code)
        goto cleanup_arcfour;
    input.data = ( void * ) input_buf;
    input.length = input_len;
    output.data = (void * ) output_buf;
    output.length = input_len;
    code =  ((*kaccess.arcfour_enc_provider->encrypt)(
                 &seq_enc_key, 0,
                 &input, &output));
cleanup_arcfour:
    memset ((void *) seq_enc_key.contents, 0, seq_enc_key.length);
    memset ((void *) usage_key.contents, 0, usage_key.length);
    free ((void *) usage_key.contents);
    free ((void *) seq_enc_key.contents);
    return (code);
}

/* AEAD */
static krb5_error_code
kg_translate_iov(context, proto, ec, rrc, key, iov_count, iov, pkiov_count, pkiov)
    krb5_context context;
    int proto;
    int ec;
    int rrc;
    const krb5_keyblock *key;
    size_t iov_count;
    gss_iov_buffer_desc *iov;
    size_t *pkiov_count;
    krb5_crypto_iov **pkiov;
{
    gss_iov_buffer_desc *header;
    gss_iov_buffer_desc *trailer;
    size_t i = 0, j;
    size_t kiov_count;
    krb5_crypto_iov *kiov;
    size_t k5_headerlen = 0;
    size_t k5_trailerlen = 0;
    krb5_error_code code;

    *pkiov_count = 0;
    *pkiov = NULL;

    header = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TOKEN);
    assert(header != NULL);

    trailer = kg_locate_iov(iov_count, iov, GSS_IOV_BUFFER_TYPE_TRAILER);

    /* Check we are V1, DCE, or have a trailer */
    assert(proto == 0 || rrc != 0 || trailer != NULL);

    if (proto == 1) {
	size_t req_headerlen, req_trailerlen;

	code = krb5_c_crypto_length(context, key->enctype, KRB5_CRYPTO_TYPE_HEADER, &k5_headerlen);
	if (code != 0)
	    return code;

	code = krb5_c_crypto_length(context, key->enctype, KRB5_CRYPTO_TYPE_TRAILER, &k5_trailerlen);
	if (code != 0)
	    return code;

	/*
	 * Sanity check header size, allowing for Windows bug where the
	 * real rotation count is EC + RRC.
	 */
	req_headerlen = 16 /* GSS-Header */ + k5_headerlen; /* Kerb-Header */
	req_trailerlen = 16 /* E(GSS-Header) */ + k5_trailerlen; /* Kerb-Trailer */

	if (trailer != NULL) {
	    if (trailer->buffer.length != req_trailerlen)
		return KRB5_BAD_MSIZE;
	} else {
	    /* No trailer, must be rotating with DCE */
	    if (rrc != 16 + k5_trailerlen)
		return KRB5_BAD_MSIZE;

	    req_headerlen += req_trailerlen; /* because trailer is rotated */
	    req_headerlen += ec;
	}
	if (header->buffer.length != req_headerlen)
	    return KRB5_BAD_MSIZE;
    }

    kiov_count = 3 + iov_count;
    kiov = (krb5_crypto_iov *)malloc(kiov_count + sizeof(krb5_crypto_iov));
    if (kiov == NULL)
	return ENOMEM;

    kiov[i].flags = KRB5_CRYPTO_TYPE_HEADER;
    if (proto) {
	/* For CFX, place the krb5 header after the GSS header, offset
	 * by the real rotation count which, owing to a bug in Windows,
	 * is actually EC + RRC */
	kiov[i].data.length = k5_headerlen;
	kiov[i].data.data = (char *)header->buffer.value + 16 + ec + rrc;
    } else {
	kiov[i].data.length = 0;
	kiov[i].data.data = NULL;
    }
    i++;

    kiov[i].flags = KRB5_CRYPTO_TYPE_TRAILER;
    if (proto) {
	/* For CFX, place the krb5 trailer in the GSS trailer, or if
	 * rotating, after the encrypted copy of the krb5 header. */
	kiov[i].data.length = k5_trailerlen;
	if (rrc)
	    kiov[i].data.data = (char *)header->buffer.value + 16 + ec + rrc - k5_trailerlen;
	else
	    kiov[i].data.data = (char *)trailer->buffer.value + 16; /* E(Header) */
    } else {
	kiov[i].data.length = 0;
	kiov[i].data.data = NULL;
    }
    i++;

    if (proto == 0) {
	/* For pre-CFX, the confounder is encrypted before the data */
	kiov[i].flags = KRB5_CRYPTO_TYPE_DATA;
	kiov[i].data.length = kg_confounder_size(context, (krb5_keyblock *)key);
	kiov[i].data.data = (char *)header->buffer.value + header->buffer.length - kiov[i].data.length;
	i++;
    }

    for (j = 0; j < iov_count; j++) {
	kiov[i].flags = kg_translate_flag_iov(iov[j].type, iov[j].flags);
	kiov[i].data.length = iov[j].buffer.length;
	kiov[i].data.data = (char *)iov[j].buffer.value;
	i++;
    }

    if (proto == 1) {
	/* CFX will insert the confounder into the header, but we do need
	 * to add the header to the end of the plaintext such that it will
	 * be integrity protected.  */
	kiov[i].flags = KRB5_CRYPTO_TYPE_DATA;
	kiov[i].data.length = 16; /* E(Header) */
	if (rrc)
	    kiov[i].data.data = (char *)header->buffer.value + 16 + ec;
	else
	    kiov[i].data.data = (char *)trailer->buffer.value;
	memcpy(kiov[i].data.data, header->buffer.value, 16);
	i++;
    }

    *pkiov_count = kiov_count;
    *pkiov = kiov;

    return 0;
}

krb5_error_code
kg_encrypt_iov(context, proto, ec, rrc, key, usage, iv, iov_count, iov)
    krb5_context context;
    int proto;
    int ec;
    int rrc;
    krb5_keyblock *key;
    int usage;
    krb5_pointer iv;
    size_t iov_count;
    gss_iov_buffer_desc *iov;
{
    krb5_error_code code;
    size_t blocksize;
    krb5_data ivd, *pivd;
    size_t kiov_count;
    krb5_crypto_iov *kiov;

    if (iv) {
        code = krb5_c_block_size(context, key->enctype, &blocksize);
        if (code)
            return(code);

        ivd.length = blocksize;
        ivd.data = malloc(ivd.length);
        if (ivd.data == NULL)
            return ENOMEM;
        memcpy(ivd.data, iv, ivd.length);
        pivd = &ivd;
    } else {
        pivd = NULL;
    }

    code = kg_translate_iov(context, proto, ec, rrc, key, iov_count, iov, &kiov_count, &kiov);
    if (code == 0) {
	code = krb5_c_encrypt_iov(context, key, usage, pivd, kiov, kiov_count);
	free(kiov);
    }

    if (pivd != NULL)
        free(pivd->data);
    return code;
}

/* length is the length of the cleartext. */

krb5_error_code
kg_decrypt_iov(context, proto, ec, rrc, key, usage, iv, iov_count, iov)
    krb5_context context;
    int proto;
    int ec;
    int rrc;
    krb5_keyblock *key;
    int usage;
    krb5_pointer iv;
    size_t iov_count;
    gss_iov_buffer_desc *iov;
{
    krb5_error_code code;
    size_t blocksize;
    krb5_data ivd, *pivd;
    size_t kiov_count;
    krb5_crypto_iov *kiov;

    if (iv) {
        code = krb5_c_block_size(context, key->enctype, &blocksize);
        if (code)
            return(code);

        ivd.length = blocksize;
        ivd.data = malloc(ivd.length);
        if (ivd.data == NULL)
            return ENOMEM;
        memcpy(ivd.data, iv, ivd.length);
        pivd = &ivd;
    } else {
        pivd = NULL;
    }

    code = kg_translate_iov(context, proto, ec, rrc, key, iov_count, iov, &kiov_count, &kiov);
    if (code == 0) {
	code = krb5_c_decrypt_iov(context, key, usage, pivd, kiov, kiov_count);
	free(kiov);
    }

    if (pivd != NULL)
        free(pivd->data);

    return code;
}

krb5_error_code
kg_arcfour_docrypt_iov (krb5_context context,
			const krb5_keyblock *longterm_key , int ms_usage,
                        const unsigned char *kd_data, size_t kd_data_len,
                        size_t iov_count, gss_iov_buffer_desc *iov)
{
    krb5_error_code code;
    krb5_data input, output;
    krb5int_access kaccess;
    krb5_keyblock seq_enc_key, usage_key;
    unsigned char t[4];
    size_t kiov_count = 0;
    krb5_crypto_iov *kiov = NULL;

    usage_key.length = longterm_key->length;
    usage_key.contents = malloc(usage_key.length);
    if (usage_key.contents == NULL)
        return (ENOMEM);
    seq_enc_key.length = longterm_key->length;
    seq_enc_key.contents = malloc(seq_enc_key.length);
    if (seq_enc_key.contents == NULL) {
        free ((void *) usage_key.contents);
        return (ENOMEM);
    }
    code = krb5int_accessor (&kaccess, KRB5INT_ACCESS_VERSION);
    if (code)
        goto cleanup_arcfour;

    t[0] = ms_usage &0xff;
    t[1] = (ms_usage>>8) & 0xff;
    t[2] = (ms_usage>>16) & 0xff;
    t[3] = (ms_usage>>24) & 0xff;
    input.data = (void *) &t;
    input.length = 4;
    output.data = (void *) usage_key.contents;
    output.length = usage_key.length;
    code = (*kaccess.krb5_hmac_iov) (kaccess.md5_hash_provider,
                                     longterm_key, kiov, kiov_count, &output);
    if (code)
        goto cleanup_arcfour;

    input.data = ( void *) kd_data;
    input.length = kd_data_len;
    output.data = (void *) seq_enc_key.contents;
    code = (*kaccess.krb5_hmac_iov) (kaccess.md5_hash_provider,
                                     &usage_key, kiov, kiov_count, &output);
    if (code)
        goto cleanup_arcfour;

    code = kg_translate_iov(context, 0, 0, longterm_key, iov_count, iov, &kiov_count, &kiov);
    if (code)
	goto cleanup_arcfour;

    code =  ((*kaccess.arcfour_enc_provider->encrypt_iov)(
                 &seq_enc_key, 0,
                 kiov, kiov_count));
cleanup_arcfour:
    memset ((void *) seq_enc_key.contents, 0, seq_enc_key.length);
    memset ((void *) usage_key.contents, 0, usage_key.length);
    free ((void *) usage_key.contents);
    free ((void *) seq_enc_key.contents);
    if (kiov != NULL)
	free(kiov);
    return (code);
}

krb5_cryptotype
kg_translate_flag_iov(OM_uint32 type, OM_uint32 flags)
{
    krb5_cryptotype ktype;

    switch (type) {
    case GSS_IOV_BUFFER_TYPE_PADDING:
	ktype = KRB5_CRYPTO_TYPE_PADDING;
	break;
    case GSS_IOV_BUFFER_TYPE_DATA:
	if (flags & GSS_IOV_BUFFER_FLAG_SIGN_ONLY)
	    ktype = KRB5_CRYPTO_TYPE_SIGN_ONLY;
	else
	    ktype = KRB5_CRYPTO_TYPE_DATA;
	break;
    case GSS_IOV_BUFFER_TYPE_EMPTY:
    case GSS_IOV_BUFFER_TYPE_TOKEN:
    case GSS_IOV_BUFFER_TYPE_TRAILER:
    default:
	ktype = KRB5_CRYPTO_TYPE_EMPTY;
	break;
    }

    return ktype;
}

gss_iov_buffer_t
kg_locate_iov(size_t iov_count,
	      gss_iov_buffer_desc *iov,
	      OM_uint32 type)
{
    size_t i;
    gss_iov_buffer_desc *p = NULL;

    if (iov == NULL)
	return NULL;

    for (i = 0; i < iov_count; i++) {
	if (iov[i].type == type)
	    p = &iov[i];
	else
	    return NULL;
    }

    return p;
}

void
kg_iov_msglen(size_t iov_count,
	      gss_iov_buffer_desc *iov,
	      size_t *data_length_p,
	      size_t *assoc_data_length_p)
{
    size_t i;
    size_t data_length = 0, assoc_data_length = 0;

    assert(iov != NULL);

    *data_length_p = *assoc_data_length_p = 0;

    for (i = 0; i < iov_count; i++) {
	if (iov[i].type != GSS_IOV_BUFFER_TYPE_DATA)
	    continue;

	if (iov[i].flags & GSS_IOV_BUFFER_FLAG_SIGN_ONLY)
	    assoc_data_length += iov[i].buffer.length;

	data_length += iov[i].buffer.length;
    }

    *data_length_p = data_length;
    *assoc_data_length_p = assoc_data_length;
}

void
kg_release_iov(size_t iov_count,
	       gss_iov_buffer_desc *iov)
{
    size_t i;
    OM_uint32 min_stat;

    assert(iov != NULL);

    for (i = 0; i < iov_count; i++) {
	if (iov[i].flags & GSS_IOV_BUFFER_FLAG_ALLOCATED) {
	    gss_release_buffer(&min_stat, &iov[i].buffer);
	    iov[i].flags &= ~(GSS_IOV_BUFFER_FLAG_ALLOCATED);
	}
    }
}

OM_uint32
kg_fixup_padding_iov(OM_uint32 *minor_status,
		     int proto,
		     int ec,
		     size_t iov_count,
		     gss_iov_buffer_desc *iov)
{
    size_t i;
    gss_iov_buffer_t padding = NULL;
    gss_iov_buffer_t data = NULL;
    size_t padlength;

    for (i = iov_count - 1; i >= 0; i--) {
	gss_iov_buffer_t piov = &iov[i];

	if (piov->type == GSS_IOV_BUFFER_TYPE_PADDING) {
	    if (padding != NULL) {
		*minor_status = EINVAL;
		return GSS_S_FAILURE;
	    }

	    padding = piov;
	} else if (data == NULL &&
	    piov->type == GSS_IOV_BUFFER_TYPE_DATA &&
	    (piov->flags & GSS_IOV_BUFFER_FLAG_SIGN_ONLY) == 0) {
	    data = piov; /* last data that was encrypted */
	}
    }

    if (data == NULL)
	return GSS_S_COMPLETE;

    if (padding == NULL) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    if (proto == 1) {
	padlength = ec;
    } else {
	unsigned char *p = (unsigned char *)data->buffer.value;
	padlength = p[data->buffer.length - 1];
    }

    if (data->buffer.length < padlength) {
	*minor_status = KRB5_BAD_MSIZE;
	return GSS_S_DEFECTIVE_TOKEN;
    }

    data->buffer.length -= padlength;

    padding->buffer.length = padlength;
    padding->buffer.value = (unsigned char *)data->buffer.value + data->buffer.length;

    return GSS_S_COMPLETE;
}

int kg_map_toktype(int proto, int toktype)
{
    int toktype2;

    if (proto)
        switch (toktype) {
        case KG_TOK_SIGN_MSG:
            toktype2 = 0x0404;
            break;
        case KG_TOK_SEAL_MSG:
            toktype2 = 0x0504;
            break;
        case KG_TOK_DEL_CTX:
            toktype2 = 0x0405;
            break;
        default:
            toktype2 = toktype;
            break;
        }
    else
        toktype2 = toktype;

    return toktype2;
}

krb5_boolean kg_integ_only_iov(size_t iov_count, gss_iov_buffer_desc *iov)
{
    size_t i;
    krb5_boolean integ_only = FALSE;

    for (i = 0; i < iov_count; i++) {
	if (iov[i].type != GSS_IOV_BUFFER_TYPE_DATA)
	    continue;
	if ((iov[i].flags & GSS_IOV_BUFFER_FLAG_SIGN_ONLY) == FALSE) {
	    integ_only = TRUE;
	    break;
	}
    }

    return integ_only;
}

krb5_error_code kg_allocate_iov(gss_iov_buffer_t iov, size_t size)
{
    assert(iov->flags & GSS_IOV_BUFFER_FLAG_ALLOCATE);

    iov->buffer.length = size;
    iov->buffer.value = xmalloc(size);
    if (iov->buffer.value == NULL) {
	iov->buffer.length = 0;
	return ENOMEM;
    }

    iov->flags |= GSS_IOV_BUFFER_FLAG_ALLOCATED;

    return 0;
}
