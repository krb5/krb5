/*
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

#include "gssapiP_krb5.h"

static krb5_error_code
make_seal_token(context, enc_ed, seq_ed, seqnum, direction, text, token,
		signalg, cksum_size, sealalg, encrypt, toktype,
		bigend, oid)
     krb5_context context;
     krb5_gss_enc_desc *enc_ed;
     krb5_gss_enc_desc *seq_ed;
     krb5_int32 *seqnum;
     int direction;
     gss_buffer_t text;
     gss_buffer_t token;
     int signalg;
     int cksum_size;
     int sealalg;
     int encrypt;
     int toktype;
     int bigend;
     gss_OID oid;
{
   krb5_error_code code;
   char *data_ptr;
   krb5_checksum md5cksum;
   krb5_checksum cksum;
   int conflen=0, tmsglen, tlen;
   unsigned char *t, *ptr;

   /* create the token buffer */

   if (toktype == KG_TOK_SEAL_MSG) {
      if (bigend && !encrypt) {
	 tmsglen = text->length;
      } else {
	 conflen = kg_confounder_size(enc_ed);
	 /* XXX knows that des block size is 8 */
	 tmsglen = (conflen+text->length+8)&(~7);
      }
   } else {
      tmsglen = 0;
   }

   tlen = g_token_size((gss_OID) oid, 14+cksum_size+tmsglen);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL)
      return(ENOMEM);

   /*** fill in the token */

   ptr = t;

   g_make_token_header((gss_OID) oid, 14+cksum_size+tmsglen, &ptr, toktype);

   /* 0..1 SIGN_ALG */

   ptr[0] = signalg;
   ptr[1] = 0;
   
   /* 2..3 SEAL_ALG or Filler */

   if ((toktype == KG_TOK_SEAL_MSG) && encrypt) {
      ptr[2] = sealalg;
      ptr[3] = 0;
   } else {
      /* No seal */
      ptr[2] = 0xff;
      ptr[3] = 0xff;
   }

   /* 4..5 Filler */

   ptr[4] = 0xff;
   ptr[5] = 0xff;

   /* pad the plaintext, encrypt if needed, and stick it in the token */

   /* initialize the the cksum and allocate the contents buffer */
   md5cksum.checksum_type = CKSUMTYPE_RSA_MD5;
   md5cksum.length = krb5_checksum_size(context, CKSUMTYPE_RSA_MD5);
   if ((md5cksum.contents = (krb5_octet *) xmalloc(md5cksum.length)) == NULL) {
      return(ENOMEM);
   }
 
   if (toktype == KG_TOK_SEAL_MSG) {
      unsigned char *plain;
      unsigned char pad;

      if (!bigend || encrypt) {
	 if ((plain = (unsigned char *) xmalloc(tmsglen)) == NULL) {
	    xfree(md5cksum.contents);
	    xfree(t);
	    return(ENOMEM);
	 }

	 if ((code = kg_make_confounder(enc_ed, plain))) {
	    xfree(plain);
	    xfree(md5cksum.contents);
	    xfree(t);
	    return(code);
	 }

	 memcpy(plain+conflen, text->value, text->length);

	 /* XXX 8 is DES cblock size */
	 pad = 8-(text->length%8);

	 memset(plain+conflen+text->length, pad, pad);
      } else {
	 /* plain is never used in the bigend && !encrypt case */
	 plain = NULL;
      }

      if (encrypt) {
	 if ((code = kg_encrypt(context, enc_ed, NULL, (krb5_pointer) plain,
				(krb5_pointer) (ptr+cksum_size+14),
				tmsglen))) {
	    if (plain)
	       xfree(plain);
	    xfree(md5cksum.contents);
	    xfree(t);
	    return(code);
	 }
      } else {
	 if (bigend)
	    memcpy(ptr+14+cksum_size, text->value, text->length);
	 else
 	    memcpy(ptr+14+cksum_size, plain, tmsglen);
      }

      /* compute the checksum */

      /* 8 = head of token body as specified by mech spec */
      if (! (data_ptr =
	     (char *) xmalloc(8 + (bigend ? text->length : tmsglen)))) {
	  if (plain)
	      xfree(plain);
	  xfree(md5cksum.contents);
	  xfree(t);
	  return(ENOMEM);
      }
      (void) memcpy(data_ptr, ptr-2, 8);
      if (bigend)
	  (void) memcpy(data_ptr+8, text->value, text->length);
      else
	  (void) memcpy(data_ptr+8, plain, tmsglen);
      code = krb5_calculate_checksum(context, md5cksum.checksum_type, data_ptr,
				     8 + (bigend ? text->length : tmsglen),
				     0, 0, &md5cksum);
      xfree(data_ptr);

      if (code) {
	  if (plain)
	      xfree(plain);
	  xfree(md5cksum.contents);
	  xfree(t);
	  return(code);
	  memcpy(ptr+14+cksum_size, plain, tmsglen);
      }

      if (plain)
	 xfree(plain);
   } else {
      /* compute the checksum */

      if (! (data_ptr = (char *) xmalloc(8 + text->length))) {
	  xfree(md5cksum.contents);
	  xfree(t);
	  return(ENOMEM);
      }
      (void) memcpy(data_ptr, ptr-2, 8);
      (void) memcpy(data_ptr+8, text->value, text->length);
      code = krb5_calculate_checksum(context, md5cksum.checksum_type, data_ptr,
				     8 + text->length,
				     0, 0, &md5cksum);
      xfree(data_ptr);
      if (code) {
	  xfree(md5cksum.contents);
	  xfree(t);
	  return(code);
      }
   }

   switch(signalg) {
   case 0:
   case 3:

#if 0
       /* XXX this depends on the key being a single-des key */

       /* DES CBC doesn't use a zero IV like it should in some
	  krb5 implementations (beta5+).  So we just do the
	  DES encryption the long way, and keep the last block
	  as the MAC */

       /* initialize the the cksum and allocate the contents buffer */
       cksum.checksum_type = CKSUMTYPE_DESCBC;
       cksum.length = krb5_checksum_size(context, CKSUMTYPE_DESCBC);
       if ((cksum.contents = (krb5_octet *) xmalloc(cksum.length)) == NULL)
	   return(ENOMEM);

       if (code = krb5_calculate_checksum(context, cksum.checksum_type,
					  md5cksum.contents, 16,
					  seq_ed->key->contents, 
					  seq_ed->key->length,
					  &cksum)) {
	  xfree(cksum.contents);
	  xfree(md5cksum.contents);
	  xfree(t);
	  return(code);
       }

       memcpy(ptr+14, cksum.contents, 8);

       xfree(cksum.contents);
#else
       if ((code = kg_encrypt(context, seq_ed,
			      (g_OID_equal(oid, gss_mech_krb5_old) ?
			       seq_ed->key->contents : NULL),
			      md5cksum.contents, md5cksum.contents, 16))) {
	  xfree(md5cksum.contents);
	  xfree(t);
	  return code;
       }
       
       cksum.length = cksum_size;
       cksum.contents = md5cksum.contents + 16 - cksum.length;

       memcpy(ptr+14, cksum.contents, cksum.length);
#endif

       break;
   }

   xfree(md5cksum.contents);

   /* create the seq_num */

   if ((code = kg_make_seq_num(context, seq_ed, direction?0:0xff, *seqnum,
			       ptr+14, ptr+6))) {
      xfree(t);
      return(code);
   }

   /* that's it.  return the token */

   (*seqnum)++;

   token->length = tlen;
   token->value = (void *) t;

   return(0);
}

/* if signonly is true, ignore conf_req, conf_state, 
   and do not encode the ENC_TYPE, MSG_LENGTH, or MSG_TEXT fields */

OM_uint32
kg_seal(context, minor_status, context_handle, conf_req_flag, qop_req, 
	input_message_buffer, conf_state, output_message_buffer, toktype)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     int conf_req_flag;
     int qop_req;
     gss_buffer_t input_message_buffer;
     int *conf_state;
     gss_buffer_t output_message_buffer;
     int toktype;
{
   krb5_gss_ctx_id_rec *ctx;
   krb5_error_code code;
   krb5_timestamp now;

   output_message_buffer->length = 0;
   output_message_buffer->value = NULL;

   /* only default qop is allowed */
   if (qop_req != GSS_C_QOP_DEFAULT) {
      *minor_status = (OM_uint32) G_UNKNOWN_QOP;
      return(GSS_S_FAILURE);
   }

   /* validate the context handle */
   if (! kg_validate_ctx_id(context_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_rec *) context_handle;

   if (! ctx->established) {
      *minor_status = KG_CTX_INCOMPLETE;
      return(GSS_S_NO_CONTEXT);
   }

   if ((code = krb5_timeofday(context, &now))) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if ((code = make_seal_token(context, &ctx->enc, &ctx->seq,
			       &ctx->seq_send, ctx->initiate,
			       input_message_buffer, output_message_buffer,
			       ctx->signalg, ctx->cksum_size, ctx->sealalg,
			       conf_req_flag, toktype, ctx->big_endian,
			       ctx->mech_used))) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if ((toktype == KG_TOK_SEAL_MSG) && conf_state)
      *conf_state = conf_req_flag;

   *minor_status = 0;
   return((ctx->endtime < now)?GSS_S_CONTEXT_EXPIRED:GSS_S_COMPLETE);
}
