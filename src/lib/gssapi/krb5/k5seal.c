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
#include "rsa-md5.h"

static krb5_error_code
make_seal_token(context, enc_ed, seq_ed, seqnum, direction, text, token,
		encrypt, toktype, bigend)
     krb5_context context;
     krb5_gss_enc_desc *enc_ed;
     krb5_gss_enc_desc *seq_ed;
     krb5_int32 *seqnum;
     int direction;
     gss_buffer_t text;
     gss_buffer_t token;
     int encrypt;
     int toktype;
     int bigend;
{
   krb5_error_code code;
   MD5_CTX md5;
   krb5_checksum desmac;
   int tmsglen, tlen;
   unsigned char *t, *ptr;

   /* create the token buffer */

   if (toktype == KG_TOK_SEAL_MSG) {
      if (bigend && !encrypt)
	 tmsglen = text->length;
      else
	 tmsglen = (kg_confounder_size(enc_ed)+text->length+8)&(~7);
   } else {
      tmsglen = 0;
   }

   tlen = g_token_size(gss_mech_krb5, 22+tmsglen);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL)
      return(ENOMEM);

   /*** fill in the token */

   ptr = t;

   g_make_token_header(gss_mech_krb5, 22+tmsglen, &ptr, toktype);

   /* for now, only generate DES integrity */

   ptr[0] = 0;
   ptr[1] = 0;

   /* SEAL_ALG, or filler */

   if ((toktype == KG_TOK_SEAL_MSG) && encrypt) {
      ptr[2] = 0;
      ptr[3] = 0;
   } else {
      ptr[2] = 0xff;
      ptr[3] = 0xff;
   }

   /* filler */

   ptr[4] = 0xff;
   ptr[5] = 0xff;

   /* pad the plaintext, encrypt if needed, and stick it in the token */

   if (toktype == KG_TOK_SEAL_MSG) {
      unsigned char *plain;
      unsigned char pad;

      if ((plain = (unsigned char *) xmalloc(tmsglen)) == NULL) {
	 xfree(t);
	 return(ENOMEM);
      }

      if (code = kg_make_confounder(enc_ed, plain)) {
	 xfree(plain);
	 xfree(t);
	 return(code);
      }

      memcpy(plain+8, text->value, text->length);

      pad = 8-(text->length%8);

      memset(plain+8+text->length, pad, pad);

      if (encrypt) {
	 if (code = kg_encrypt(enc_ed, NULL, (krb5_pointer) plain,
			       (krb5_pointer) (ptr+22), tmsglen)) {
	    xfree(plain);
	    xfree(t);
	    return(code);
	 }
      } else {
	 if (bigend)
	    memcpy(ptr+22, text->value, text->length);
	 else
	    memcpy(ptr+22, plain, tmsglen);
      }

      /* compute the checksum */

      MD5Init(&md5);
      MD5Update(&md5, (unsigned char *) ptr-2, 8);
      if (bigend)
	 MD5Update(&md5, text->value, text->length);
      else
	 MD5Update(&md5, plain, tmsglen);
      MD5Final(&md5);

      xfree(plain);
   } else {
      /* compute the checksum */

      MD5Init(&md5);
      MD5Update(&md5, (unsigned char *) ptr-2, 8);
      MD5Update(&md5, text->value, text->length);
      MD5Final(&md5);
   }

   /* XXX this depends on the key being a single-des key, but that's
      all that kerberos supports right now */

   if (code = krb5_calculate_checksum(context, CKSUMTYPE_DESCBC, md5.digest, 16,
				      seq_ed->key->contents, 
				      seq_ed->key->length,
				      &desmac)) {
      xfree(t);
      return(code);
   }

   memcpy(ptr+14, desmac.contents, 8);

   /* XXX krb5_free_checksum_contents? */
   xfree(desmac.contents);

   /* create the seq_num */

   if (code = kg_make_seq_num(seq_ed, direction?0:0xff, *seqnum,
			      ptr+14, ptr+6)) {
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
kg_seal(minor_status, context_handle, conf_req_flag, qop_req, 
	input_message_buffer, conf_state, output_message_buffer, toktype)
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

   if (code = krb5_timeofday(ctx->context, &now)) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (code = make_seal_token(ctx->context, &ctx->enc, &ctx->seq,
			      &ctx->seq_send, ctx->initiate,
			      input_message_buffer, output_message_buffer,
			      conf_req_flag, toktype, ctx->big_endian)) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if ((toktype == KG_TOK_SEAL_MSG) && conf_state)
      *conf_state = conf_req_flag;

   *minor_status = 0;
   return((ctx->endtime < now)?GSS_S_CONTEXT_EXPIRED:GSS_S_COMPLETE);
}
