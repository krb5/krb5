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
 * This module contains routines to [de]serialize 
 *	krb5_gss_enc_desc and krb5_gss_ctx_id_t.
 * XXX This whole serialization abstraction is unnecessary in a
 * non-messaging environment, which krb5 is.  Someday, this should
 * all get redone without the extra level of indirection. I've done
 * some of this work here, since adding new serializers is an internal
 * krb5 interface, and I won't use those.  There is some more
 * deobfuscation (no longer anonymizing pointers, mostly) which could
 * still be done. --marc
 */

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

static krb5_error_code
kg_oid_externalize(kcontext, arg, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	arg;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
     gss_OID oid = (gss_OID) arg;
     
     (void) krb5_ser_pack_int32((krb5_int32) oid->length,
				buffer, lenremain);
     (void) krb5_ser_pack_bytes((krb5_octet *) oid->elements,
				oid->length, buffer, lenremain);
}

static krb5_error_code
kg_oid_internalize(kcontext, argp, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	*argp;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
     gss_OID oid;
     krb5_int32 ibuf;

     oid = (gss_OID) malloc(sizeof(gss_OID_desc));
     if (oid == NULL)
	  return ENOMEM;
     (void) krb5_ser_unpack_int32(&ibuf, buffer, lenremain);
     oid->length = ibuf;
     (void) krb5_ser_unpack_bytes((krb5_octet *) oid->elements,
				  oid->length, buffer, lenremain);
     return 0;
}

krb5_error_code
kg_oid_size(kcontext, arg, sizep)
    krb5_context	kcontext;
    krb5_pointer	arg;
    size_t		*sizep;
{
   krb5_error_code kret;
   gss_OID oid;
   size_t required;

   kret = EINVAL;
   if ((oid = (gss_OID) arg)) {
      required = sizeof(krb5_int32);
      required += oid->length;

      kret = 0;

      *sizep += required;
   }

   return(kret);
}

/*
 * Determine the size required for this krb5_gss_ctx_id_rec.
 */
krb5_error_code
kg_ctx_size(kcontext, arg, sizep)
    krb5_context	kcontext;
    krb5_pointer	arg;
    size_t		*sizep;
{
    krb5_error_code	kret;
    krb5_gss_ctx_id_rec	*ctx;
    size_t		required;

    /*
     * krb5_gss_ctx_id_rec requires:
     *	krb5_int32	for KG_CONTEXT
     *	krb5_int32	for initiate.
     *	krb5_int32	for mutual.
     *	krb5_int32	for seed_init.
     *	sizeof(seed)	for seed
     *  krb5_int32	for signalg.
     *  krb5_int32	for cksum_size.
     *  krb5_int32	for sealalg.
     *	krb5_int32	for endtime.
     *	krb5_int32	for flags.
     *	krb5_int32	for seq_send.
     *	krb5_int32	for seq_recv.
     *	krb5_int32	for established.
     *	krb5_int32	for big_endian.
     *	krb5_int32	for trailer.
     */
    kret = EINVAL;
    if ((ctx = (krb5_gss_ctx_id_rec *) arg)) {
	required = 14*sizeof(krb5_int32);
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
	    kret = kg_enc_desc_size(kcontext,
				    (krb5_pointer) &ctx->enc,
				    &required);

	if (!kret)
	    kret = kg_enc_desc_size(kcontext,
				    (krb5_pointer) &ctx->seq,
				    &required);

	if (!kret)
	    kret = kg_oid_size(kcontext,
			       (krb5_pointer) ctx->mech_used,
			       &required);

	if (!kret)
	    *sizep += required;
    }
    return(kret);
}

/*
 * Externalize this krb5_gss_ctx_id_ret.
 */
krb5_error_code
kg_ctx_externalize(kcontext, arg, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	arg;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_gss_ctx_id_rec	*ctx;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((ctx = (krb5_gss_ctx_id_rec *) arg)) {
	kret = ENOMEM;
	if (!kg_ctx_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    /* Our identifier */
	    (void) krb5_ser_pack_int32(KG_CONTEXT, &bp, &remain);

	    /* Now static data */
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->initiate,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->gss_flags,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->seed_init,
				       &bp, &remain);
	    (void) krb5_ser_pack_bytes((krb5_octet *) ctx->seed,
				       sizeof(ctx->seed),
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->signalg,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->cksum_size,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) ctx->sealalg,
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

	    if (!kret && ctx->mech_used)
		 kret = kg_oid_externalize(kcontext, ctx->mech_used,
					   &bp, &remain); 
	    
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
		kret = kg_enc_desc_externalize(kcontext,
					       (krb5_pointer) &ctx->enc,
					       &bp, &remain);

	    if (!kret)
		kret = kg_enc_desc_externalize(kcontext,
					       (krb5_pointer) &ctx->seq,
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
krb5_error_code
kg_ctx_internalize(kcontext, argp, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	*argp;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_gss_ctx_id_rec	*ctx;
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
	    (ctx = (krb5_gss_ctx_id_rec *)
	     xmalloc(sizeof(krb5_gss_ctx_id_rec)))) {
	    memset(ctx, 0, sizeof(krb5_gss_ctx_id_rec));

	    /* Get static data */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->initiate = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->gss_flags = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->seed_init = (int) ibuf;
	    (void) krb5_ser_unpack_bytes((krb5_octet *) ctx->seed,
					 sizeof(ctx->seed),
					 &bp, &remain);
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->signalg = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->cksum_size = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->sealalg = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->endtime = (krb5_timestamp) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->flags = (krb5_flags) ibuf;
	    (void) krb5_ser_unpack_int32(&ctx->seq_send, &bp, &remain);
	    (void) krb5_ser_unpack_int32(&ctx->seq_recv, &bp, &remain);
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->established = (int) ibuf;
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    ctx->big_endian = (int) ibuf;

	    if ((kret = kg_oid_internalize(kcontext, &ctx->mech_used, &bp,
					   &remain))) {
		 if (kret == EINVAL)
		      kret = 0;
	    }
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
		if ((kret = kg_enc_desc_internalize(kcontext,
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
		if ((kret = kg_enc_desc_internalize(kcontext,
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
