/*
 * lib/gssapi/krb5/ser_sctx.c
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
 * ser_sctx.c - Handle [de]serialization of GSSAPI security context.
 */
#include "gssapiP_krb5.h"

/*
 * This module contains routines to [de]serialize krb5_gss_cred_id_t,
 *	krb5_gss_enc_desc and krb5_gss_ctx_id_t.
 */


/* Windows needs these prototypes since the structure they're assigned
 *  into is prototyped.
 */
static krb5_error_code kg_cred_size
	PROTOTYPE((krb5_context	kcontext,
	    krb5_pointer arg,
    	size_t *sizep));

static krb5_error_code kg_cred_externalize
	PROTOTYPE((krb5_context kcontext,
	    krb5_pointer arg,
    	krb5_octet **buffer,
	    size_t *lenremain));

static krb5_error_code kg_cred_internalize
	PROTOTYPE((krb5_context kcontext,
        krb5_pointer *argp,
        krb5_octet **buffer,
        size_t *lenremain));

static krb5_error_code kg_enc_desc_size
	PROTOTYPE((krb5_context kcontext,
        krb5_pointer arg,
        size_t *sizep));

static krb5_error_code kg_enc_desc_externalize
	PROTOTYPE((krb5_context kcontext,
        krb5_pointer arg,
        krb5_octet **buffer,
        size_t *lenremain));

static krb5_error_code kg_enc_desc_internalize
	PROTOTYPE((krb5_context kcontext,
        krb5_pointer *argp,
        krb5_octet **buffer,
        size_t *lenremain));

static krb5_error_code kg_ctx_size
	PROTOTYPE((krb5_context kcontext,
        krb5_pointer arg,
        size_t *sizep));

static krb5_error_code kg_ctx_externalize
	PROTOTYPE((krb5_context kcontext,
        krb5_pointer arg,
        krb5_octet **buffer,
        size_t *lenremain));

static krb5_error_code kg_ctx_internalize
	PROTOTYPE((krb5_context kcontext,
        krb5_pointer *argp,
        krb5_octet **buffer,
        size_t *lenremain));

/*
 * Determine the size required for this krb5_gss_cred_id_t.
 */
static krb5_error_code
kg_cred_size(kcontext, arg, sizep)
    krb5_context	kcontext;
    krb5_pointer	arg;
    size_t		*sizep;
{
    krb5_error_code	kret;
    krb5_gss_cred_id_t	cred;
    size_t		required;

    /*
     * krb5_gss_cred_id_t requires:
     *	krb5_int32	for KG_CRED
     *	krb5_int32	for usage.
     *	krb5_int32	for tgt_expire.
     *	krb5_int32	for trailer.
     */
    kret = EINVAL;
    if ((cred = (krb5_gss_cred_id_t) arg)) {
	required = 4*sizeof(krb5_int32);
	kret = 0;
	if (cred->princ)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_PRINCIPAL,
				    (krb5_pointer) cred->princ,
				    &required);
	if (!kret && cred->keytab)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_KEYTAB,
				    (krb5_pointer) cred->keytab,
				    &required);

	if (!kret && cred->ccache)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_CCACHE,
				    (krb5_pointer) cred->ccache,
				    &required);
	if (!kret)
	    *sizep += required;
    }
    return(kret);
}

/*
 * Externalize this krb5_gss_cred_id_t.
 */
static krb5_error_code
kg_cred_externalize(kcontext, arg, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	arg;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_gss_cred_id_t	cred;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((cred = (krb5_gss_cred_id_t) arg)) {
	kret = ENOMEM;
	if (!kg_cred_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    /* Our identifier */
	    (void) krb5_ser_pack_int32(KG_CRED, &bp, &remain);

	    /* Now static data */
	    (void) krb5_ser_pack_int32((krb5_int32) cred->usage, &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) cred->tgt_expire,
				       &bp, &remain);

	    /* Now pack up dynamic data */
	    if (cred->princ)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_PRINCIPAL,
					       (krb5_pointer) cred->princ,
					       &bp, &remain);
	    else
		kret = 0;

	    if (!kret && cred->keytab)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_KEYTAB,
					       (krb5_pointer) cred->keytab,
					       &bp, &remain);

	    if (!kret && cred->ccache)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_CCACHE,
					     (krb5_pointer) cred->ccache,
					     &bp, &remain);

	    if (!kret) {
		(void) krb5_ser_pack_int32(KG_CRED, &bp, &remain);
		*buffer = bp;
		*lenremain = remain;
	    }
	}
    }
    return(kret);
}

/*
 * Internalize this krb5_gss_cred_id_t.
 */
static krb5_error_code
kg_cred_internalize(kcontext, argp, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	*argp;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_gss_cred_id_t	cred;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
	ibuf = 0;
    if (ibuf == KG_CRED) {
	kret = ENOMEM;

	/* Get a cred */
	if ((remain >= (2*sizeof(krb5_int32))) &&
	    (cred = (krb5_gss_cred_id_t)
	     xmalloc(sizeof(krb5_gss_cred_id_rec)))) {
	    memset(cred, 0, sizeof(krb5_gss_cred_id_rec));

	    /* Get the static data */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    cred->usage = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    cred->tgt_expire = (krb5_timestamp) ibuf;

	    /* cred->princ */
	    if ((kret = krb5_internalize_opaque(kcontext,
						KV5M_PRINCIPAL,
						(krb5_pointer *) &cred->princ,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }

	    /* cred->keytab */
	    if (!kret &&
		(kret = krb5_internalize_opaque(kcontext,
						KV5M_KEYTAB,
						(krb5_pointer *) &cred->keytab,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }

	    /* cred->ccache */
	    if (!kret &&
		(kret = krb5_internalize_opaque(kcontext,
						KV5M_CCACHE,
						(krb5_pointer *) &cred->ccache,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }

	    /* trailer */
	    if (!kret &&
		!(kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain)) &&
		(ibuf == KG_CRED)) {
		*buffer = bp;
		*lenremain = remain;
		*argp = (krb5_pointer) cred;
	    }
	    else {
		if (!kret && (ibuf != KG_CRED))
		    kret = EINVAL;
		if (cred->ccache)
		    krb5_cc_close(kcontext, cred->ccache);
		if (cred->keytab)
		    krb5_kt_close(kcontext, cred->keytab);
		if (cred->princ)
		    krb5_free_principal(kcontext, cred->princ);
		xfree(cred);
	    }
	}
    }
    return(kret);
}

/*
 * Determine the size required for this krb5_gss_enc_desc.
 */
static krb5_error_code
kg_enc_desc_size(kcontext, arg, sizep)
    krb5_context	kcontext;
    krb5_pointer	arg;
    size_t		*sizep;
{
    krb5_error_code	kret;
    krb5_gss_enc_desc	*edescp;
    size_t		required;

    /*
     * krb5_gss_cred_id_t requires:
     *	krb5_int32	for KG_ENC_DESC
     *	krb5_int32	for processed.
     *	krb5_int32	for trailer.
     */
    kret = EINVAL;
    if ((edescp = (krb5_gss_enc_desc *) arg)) {
	required = 3*sizeof(krb5_int32);
	if (edescp->key)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_KEYBLOCK,
				    (krb5_pointer) edescp->key,
				    &required);
	else
	    kret = 0;
	
	 /*
	  * We need to use size_opaque here because we're not sure as to the
	  * ancestry of this eblock, and we can't be sure that the magic number
	  * is set in it, so we ASSuME that it's ok.
	  */
	if (!kret)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_ENCRYPT_BLOCK,
				    (krb5_pointer) &edescp->eblock,
				    &required);

	if (!kret)
	    *sizep += required;
    }
    return(kret);
}

/*
 * Externalize this krb5_gss_enc_desc.
 */
static krb5_error_code
kg_enc_desc_externalize(kcontext, arg, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	arg;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_gss_enc_desc	*enc_desc;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((enc_desc = (krb5_gss_enc_desc *) arg)) {
	kret = ENOMEM;
	if (!kg_enc_desc_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    /* Our identifier */
	    (void) krb5_ser_pack_int32(KG_ENC_DESC, &bp, &remain);

	    /* Now static data */
	    (void) krb5_ser_pack_int32((krb5_int32) enc_desc->processed,
				       &bp, &remain);

	    /* Now pack up dynamic data */
	    if (enc_desc->key)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_KEYBLOCK,
					       (krb5_pointer) enc_desc->key,
					       &bp, &remain);
	    else
		kret = 0;

	    if (!kret)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_ENCRYPT_BLOCK,
					       (krb5_pointer)&enc_desc->eblock,
					       &bp, &remain);
	    if (!kret) {
		(void) krb5_ser_pack_int32(KG_ENC_DESC, &bp, &remain);
		*buffer = bp;
		*lenremain = remain;
	    }
	}
    }
    return(kret);
}

/*
 * Internalize this krb5_gss_enc_desc.
 */
static krb5_error_code
kg_enc_desc_internalize(kcontext, argp, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	*argp;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_gss_enc_desc	*edescp;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    krb5_encrypt_block	*eblockp;
    size_t		remain;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
	ibuf = 0;
    if (ibuf == KG_ENC_DESC) {
	kret = ENOMEM;

	/* Get an enc_desc */
	if ((remain >= (2*sizeof(krb5_int32))) &&
	    (edescp = (krb5_gss_enc_desc *)
	     xmalloc(sizeof(krb5_gss_enc_desc)))) {
	    memset(edescp, 0, sizeof(krb5_gss_enc_desc));

	    /* Get the static data */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    edescp->processed = (int) ibuf;

	    /* edescp->key */
	    if ((kret = krb5_internalize_opaque(kcontext,
						KV5M_KEYBLOCK,
						(krb5_pointer *) &edescp->key,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }

	    /* edescp->eblock */
	    if (!kret &&
		(kret = krb5_internalize_opaque(kcontext,
						KV5M_ENCRYPT_BLOCK,
						(krb5_pointer *) &eblockp,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }
	    else {
		/* Successful, copy in allocated eblock to our structure */
		memcpy(&edescp->eblock, eblockp, sizeof(edescp->eblock));
		krb5_xfree(eblockp);
	    }

	    /* trailer */
	    if (!kret &&
		!(kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain)) &&
		(ibuf == KG_ENC_DESC)) {
		*buffer = bp;
		*lenremain = remain;
		*argp = (krb5_pointer) edescp;
	    }
	    else {
		if (!kret && (ibuf != KG_ENC_DESC))
		    kret = EINVAL;
		if (edescp->eblock.key)
		    krb5_free_keyblock(kcontext, edescp->eblock.key);
		if (edescp->eblock.priv && edescp->eblock.priv_size)
		    krb5_xfree(edescp->eblock.priv);
		if (edescp->key)
		    krb5_free_keyblock(kcontext, edescp->key);
		xfree(edescp);
	    }
	}
    }
    return(kret);
}

/*
 * Determine the size required for this krb5_gss_ctx_id_t.
 */
static krb5_error_code
kg_ctx_size(kcontext, arg, sizep)
    krb5_context	kcontext;
    krb5_pointer	arg;
    size_t		*sizep;
{
    krb5_error_code	kret;
    krb5_gss_ctx_id_t	*ctx;
    size_t		required;

    /*
     * krb5_gss_ctx_id_t requires:
     *	krb5_int32	for KG_CONTEXT
     *	krb5_int32	for initiate.
     *	krb5_int32	for mutual.
     *	krb5_int32	for seed_init.
     *	sizeof(seed)	for seed
     *	krb5_int32	for endtime.
     *	krb5_int32	for flags.
     *	krb5_int32	for seq_send.
     *	krb5_int32	for seq_recv.
     *	krb5_int32	for established.
     *	krb5_int32	for big_endian.
     *	krb5_int32	for trailer.
     */
    kret = EINVAL;
    if ((ctx = (krb5_gss_ctx_id_t *) arg)) {
	required = 11*sizeof(krb5_int32);
	required += sizeof(ctx->seed);

	kret = 0;
	if (!kret && ctx->here)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_PRINCIPAL,
				    (krb5_pointer) ctx->here,
				    &required);

	if (!kret && ctx->there)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_PRINCIPAL,
				    (krb5_pointer) ctx->there,
				    &required);

	if (!kret && ctx->subkey)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_KEYBLOCK,
				    (krb5_pointer) ctx->subkey,
				    &required);

	if (!kret)
	    kret = krb5_size_opaque(kcontext,
				    KG_ENC_DESC,
				    (krb5_pointer) &ctx->enc,
				    &required);

	if (!kret)
	    kret = krb5_size_opaque(kcontext,
				    KG_ENC_DESC,
				    (krb5_pointer) &ctx->seq,
				    &required);

	if (!kret && ctx->auth_context)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_AUTH_CONTEXT,
				    (krb5_pointer) ctx->auth_context,
				    &required);

	if (!kret)
	    *sizep += required;
    }
    return(kret);
}

/*
 * Externalize this krb5_gss_ctx_id_t.
 */
static krb5_error_code
kg_ctx_externalize(kcontext, arg, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	arg;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_gss_ctx_id_t	*ctx;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((ctx = (krb5_gss_ctx_id_t *) arg)) {
	kret = ENOMEM;
	if (!kg_ctx_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    /* Our identifier */
	    (void) krb5_ser_pack_int32(KG_CONTEXT, &bp, &remain);

	    /* Now static data */
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->initiate,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->mutual,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->seed_init,
				       &bp, &remain);
	    (void) krb5_ser_pack_bytes((krb5_octet *) ctx->seed,
				       sizeof(ctx->seed),
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->endtime,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->flags,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->seq_send,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->seq_recv,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->established,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->big_endian,
				       &bp, &remain);

	    /* Now dynamic data */
	    kret = 0;

	    if (!kret && ctx->here)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_PRINCIPAL,
					       (krb5_pointer) ctx->here,
					       &bp, &remain);

	    if (!kret && ctx->there)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_PRINCIPAL,
					       (krb5_pointer) ctx->there,
					       &bp, &remain);

	    if (!kret && ctx->subkey)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_KEYBLOCK,
					       (krb5_pointer) ctx->subkey,
					       &bp, &remain);

	    if (!kret)
		kret = krb5_externalize_opaque(kcontext,
					       KG_ENC_DESC,
					       (krb5_pointer) &ctx->enc,
					       &bp, &remain);

	    if (!kret)
		kret = krb5_externalize_opaque(kcontext,
					       KG_ENC_DESC,
					       (krb5_pointer) &ctx->seq,
					       &bp, &remain);

	    if (!kret && ctx->auth_context)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_AUTH_CONTEXT,
					       (krb5_pointer)ctx->auth_context,
					       &bp, &remain);

	    if (!kret) {
		(void) krb5_ser_pack_int32(KG_CONTEXT, &bp, &remain);
		*buffer = bp;
		*lenremain = remain;
	    }
	}
    }
    return(kret);
}

/*
 * Internalize this krb5_gss_ctx_id_t.
 */
static krb5_error_code
kg_ctx_internalize(kcontext, argp, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	*argp;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_gss_ctx_id_t	*ctx;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;
    krb5_gss_enc_desc	*edp;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
	ibuf = 0;
    if (ibuf == KG_CONTEXT) {
	kret = ENOMEM;

	/* Get a context */
	if ((remain >= ((10*sizeof(krb5_int32))+sizeof(ctx->seed))) &&
	    (ctx = (krb5_gss_ctx_id_t *)
	     xmalloc(sizeof(krb5_gss_ctx_id_t)))) {
	    memset(ctx, 0, sizeof(krb5_gss_ctx_id_t));

	    /* Get static data */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->initiate = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->mutual = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->seed_init = (int) ibuf;
	    (void) krb5_ser_unpack_bytes((krb5_octet *) ctx->seed,
					 sizeof(ctx->seed),
					 &bp, &remain);
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->endtime = (krb5_timestamp) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->flags = (krb5_timestamp) ibuf;
	    (void) krb5_ser_unpack_int32(&ctx->seq_send, &bp, &remain);
	    (void) krb5_ser_unpack_int32(&ctx->seq_recv, &bp, &remain);
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->established = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->big_endian = (int) ibuf;

	    /* Now get substructure data */
	    if ((kret = krb5_internalize_opaque(kcontext,
						KV5M_PRINCIPAL,
						(krb5_pointer *) &ctx->here,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }
	    if (!kret &&
		(kret = krb5_internalize_opaque(kcontext,
						KV5M_PRINCIPAL,
						(krb5_pointer *) &ctx->there,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }
	    if (!kret &&
		(kret = krb5_internalize_opaque(kcontext,
						KV5M_KEYBLOCK,
						(krb5_pointer *) &ctx->subkey,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }
	    if (!kret) {
		if ((kret = krb5_internalize_opaque(kcontext,
						    KG_ENC_DESC,
						    (krb5_pointer *) &edp,
						    &bp, &remain))) {
		    if (kret == EINVAL)
			kret = 0;
		}
		else {
		    memcpy(&ctx->enc, edp, sizeof(ctx->enc));
		    xfree(edp);
		}
	    }
	    if (!kret) {
		if ((kret = krb5_internalize_opaque(kcontext,
						    KG_ENC_DESC,
						    (krb5_pointer *) &edp,
						    &bp, &remain))) {
		    if (kret == EINVAL)
			kret = 0;
		}
		else {
		    memcpy(&ctx->seq, edp, sizeof(ctx->seq));
		    xfree(edp);
		}
	    }
	    if (!kret &&
		(kret = krb5_internalize_opaque(kcontext,
						KV5M_AUTH_CONTEXT,
						(krb5_pointer *)
						&ctx->auth_context,
						&bp, &remain))) {
		if (kret == EINVAL)
		    kret = 0;
	    }

	    /* Get trailer */
	    if (!kret &&
		!(kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain)) &&
		(ibuf == KG_CONTEXT)) {
		*buffer = bp;
		*lenremain = remain;
		*argp = (krb5_pointer) ctx;
	    }
	    else {
		if (!kret && (ibuf != KG_CONTEXT))
		    kret = EINVAL;
		if (ctx->auth_context)
		    krb5_auth_con_free(kcontext, ctx->auth_context);
		if (ctx->seq.eblock.key)
		    krb5_free_keyblock(kcontext, ctx->seq.eblock.key);
		if (ctx->seq.eblock.priv && ctx->seq.eblock.priv_size)
		    krb5_xfree(ctx->seq.eblock.priv);
		if (ctx->seq.key)
		    krb5_free_keyblock(kcontext, ctx->seq.key);
		if (ctx->enc.eblock.key)
		    krb5_free_keyblock(kcontext, ctx->enc.eblock.key);
		if (ctx->enc.eblock.priv && ctx->enc.eblock.priv_size)
		    krb5_xfree(ctx->enc.eblock.priv);
		if (ctx->enc.key)
		    krb5_free_keyblock(kcontext, ctx->enc.key);
		if (ctx->subkey)
		    krb5_free_keyblock(kcontext, ctx->subkey);
		if (ctx->there)
		    krb5_free_principal(kcontext, ctx->there);
		if (ctx->here)
		    krb5_free_principal(kcontext, ctx->here);
		xfree(ctx);
	    }
	}
    }
    return(kret);
}

static const krb5_ser_entry kg_cred_ser_entry = {
    KG_CRED,				/* Type			*/
    kg_cred_size,			/* Sizer routine	*/
    kg_cred_externalize,		/* Externalize routine	*/
    kg_cred_internalize			/* Internalize routine	*/
};
static const krb5_ser_entry kg_enc_desc_ser_entry = {
    KG_ENC_DESC,			/* Type			*/
    kg_enc_desc_size,			/* Sizer routine	*/
    kg_enc_desc_externalize,		/* Externalize routine	*/
    kg_enc_desc_internalize		/* Internalize routine	*/
};
static const krb5_ser_entry kg_ctx_ser_entry = {
    KG_CONTEXT,				/* Type			*/
    kg_ctx_size,			/* Sizer routine	*/
    kg_ctx_externalize,			/* Externalize routine	*/
    kg_ctx_internalize			/* Internalize routine	*/
};

krb5_error_code
kg_ser_context_init(kcontext)
    krb5_context	kcontext;
{
    krb5_error_code	kret;

    kret = krb5_register_serializer(kcontext, &kg_cred_ser_entry);
    if (!kret)
	kret = krb5_register_serializer(kcontext, &kg_enc_desc_ser_entry);
    if (!kret)
	kret = krb5_register_serializer(kcontext, &kg_ctx_ser_entry);
    return(kret);
}
