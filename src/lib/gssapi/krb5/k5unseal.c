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
#include <memory.h>
#include "rsa-md5.h"

/* message_buffer is an input if SIGN, output if SEAL, and ignored if DEL_CTX
   conf_state is only valid if SEAL.
   */

OM_uint32
kg_unseal(minor_status, context_handle, input_token_buffer, message_buffer,
	  conf_state, qop_state, toktype)
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t input_token_buffer;
     gss_buffer_t message_buffer;
     int *conf_state;
     int *qop_state;
     int toktype;
{
   krb5_gss_ctx_id_rec *ctx;
   krb5_error_code code;
   int bodysize;
   int tmsglen;
   int signalg;
   int sealalg;
   gss_buffer_desc token;
   unsigned char *ptr;
   krb5_checksum desmac;
   MD5_CTX md5;
   unsigned char *cksum;
   krb5_timestamp now;
   unsigned char *plain;
   int plainlen;

   if ((toktype == KG_TOK_SEAL_MSG) || (toktype == KG_TOK_WRAP_MSG)) {
      message_buffer->length = 0;
      message_buffer->value = NULL;
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

   /* parse the token, leave the data in message_buffer, setting conf_state */

   /* verify the header */

   ptr = (unsigned char *) input_token_buffer->value;

   if (! g_verify_token_header((gss_OID) gss_mech_krb5, &bodysize,
			       &ptr, toktype, input_token_buffer->length)) {
      *minor_status = 0;
      return(GSS_S_DEFECTIVE_TOKEN);
   }

   if ((toktype == KG_TOK_SEAL_MSG) || (toktype == KG_TOK_WRAP_MSG))
      tmsglen = bodysize-22;

   /* get the sign and seal algorithms */

   signalg = ptr[0] + (ptr[1]<<8);
   sealalg = ptr[2] + (ptr[3]<<8);

   if (((signalg != 0) && (signalg != 1)) ||
       (((toktype != KG_TOK_SEAL_MSG) &&
	 (toktype != KG_TOK_WRAP_MSG)) && (sealalg != 0xffff)) ||
       (((toktype == KG_TOK_SEAL_MSG) ||
	 (toktype == KG_TOK_WRAP_MSG)) && 
	((sealalg != 0xffff) && (sealalg != 0))) ||
       (ptr[4] != 0xff) ||
       (ptr[5] != 0xff)) {
      *minor_status = 0;
      return(GSS_S_DEFECTIVE_TOKEN);
   }

   /* get the token parameters */

   /* decode the message, if SEAL */

   if ((toktype == KG_TOK_SEAL_MSG) || (toktype == KG_TOK_WRAP_MSG)) {
      if (sealalg == 0) {
	 if ((plain = (unsigned char *) xmalloc(tmsglen)) == NULL) {
	    *minor_status = ENOMEM;
	    return(GSS_S_FAILURE);
	 }

	 if (code = kg_decrypt(&ctx->enc, NULL, ptr+22, plain, tmsglen)) {
	    xfree(plain);
	    *minor_status = code;
	    return(GSS_S_FAILURE);
	 }
      } else {
	 plain = ptr+22;
      }

      plainlen = tmsglen;

      if (sealalg && ctx->big_endian)
	 token.length = tmsglen;
      else
	 token.length = tmsglen - 8 - plain[tmsglen-1];

      if (token.length) {
	 if ((token.value = xmalloc(token.length)) == NULL) {
	    if (sealalg == 0)
	       xfree(plain);
	    *minor_status = ENOMEM;
	    return(GSS_S_FAILURE);
	 }

	 if (sealalg && ctx->big_endian)
	    memcpy(token.value, plain, token.length);
	 else
	    memcpy(token.value, plain+8, token.length);
      }
   } else if ((toktype == KG_TOK_SIGN_MSG) || (toktype == KG_TOK_MIC_MSG)) {
      token = *message_buffer;
      plain = token.value;
      plainlen = token.length;
   } else {
      token.length = 0;
      token.value = NULL;
      plain = token.value;
      plainlen = token.length;
   }

   /* compute the checksum of the message */

   if (signalg == 0) {
      /* compute the checksum of the message */

      MD5Init(&md5);
      MD5Update(&md5, (unsigned char *) ptr-2, 8);
      if (ctx->big_endian)
	 MD5Update(&md5, token.value, token.length);
      else
	 MD5Update(&md5, plain, plainlen);
      MD5Final(&md5);

      if (sealalg == 0)
	 xfree(plain);

      /* XXX this depends on the key being a single-des key, but that's
	 all that kerberos supports right now */

      if (code = krb5_calculate_checksum(context, CKSUMTYPE_DESCBC, md5.digest,
					 16, ctx->seq.key->contents, 
					 ctx->seq.key->length,
					 &desmac)) {
	 if ((toktype == KG_TOK_SEAL_MSG) || (toktype == KG_TOK_WRAP_MSG))
	    xfree(token.value);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

      cksum = desmac.contents;
   } else {
      if (! ctx->seed_init) {
	 if (code = kg_make_seed(ctx->subkey, ctx->seed)) {
	    if (sealalg == 0)
	       xfree(plain);
	    if ((toktype == KG_TOK_SEAL_MSG) || (toktype == KG_TOK_WRAP_MSG))
	       xfree(token.value);
	    *minor_status = code;
	    return(GSS_S_FAILURE);
	 }
	 ctx->seed_init = 1;
      }

      MD5Init(&md5);
      MD5Update(&md5, ctx->seed, sizeof(ctx->seed));
      MD5Update(&md5, (unsigned char *) ptr-2, 8);
      if (ctx->big_endian)
	 MD5Update(&md5, token.value, token.length);
      else
	 MD5Update(&md5, plain, plainlen);
      MD5Final(&md5);

      if (sealalg == 0)
	 xfree(plain);

      cksum = md5.digest;
   }
      
   /* compare the computed checksum against the transmitted checksum */

   if (memcmp(cksum, ptr+14, 8) != 0) {
      if (signalg == 0)
	 xfree(desmac.contents);
      if ((toktype == KG_TOK_SEAL_MSG) || (toktype == KG_TOK_WRAP_MSG))
	 xfree(token.value);
      *minor_status = 0;
      return(GSS_S_BAD_SIG);
   }

   if (signalg == 0)
      xfree(desmac.contents);

   /* XXX this is where the seq_num check would go */
   
   /* it got through unscathed.  Make sure the context is unexpired */

   if ((toktype == KG_TOK_SEAL_MSG) || (toktype = KG_TOK_WRAP_MSG))
      *message_buffer = token;

   if (conf_state)
      *conf_state = (sealalg == 0);

   if (qop_state)
      *qop_state = GSS_C_QOP_DEFAULT;

   if (code = krb5_timeofday(ctx->context, &now)) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (now > ctx->endtime) {
      *minor_status = 0;
      return(GSS_S_CONTEXT_EXPIRED);
   }

   /* success */

   *minor_status = 0;
   return(GSS_S_COMPLETE);
}
