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

OM_uint32
krb5_gss_delete_sec_context(context, minor_status, context_handle, output_token)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_ctx_id_t *context_handle;
     gss_buffer_t output_token;
{
   krb5_gss_ctx_id_rec *ctx;

   if (output_token) {
      output_token->length = 0;
      output_token->value = NULL;
   }

   /*SUPPRESS 29*/
   if (*context_handle == GSS_C_NO_CONTEXT) {
      *minor_status = 0;
      return(GSS_S_COMPLETE);
   }

   /*SUPPRESS 29*/
   /* validate the context handle */
   if (! kg_validate_ctx_id(*context_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_NO_CONTEXT);
   }

   /* construct a delete context token if necessary */

   if (output_token) {
      OM_uint32 major;
      gss_buffer_desc empty;
      empty.length = 0; empty.value = NULL;

      if (major = kg_seal(minor_status, *context_handle, 0, GSS_C_QOP_DEFAULT,
			  &empty, NULL, output_token, KG_TOK_DEL_CTX))
	 return(major);
   }

   /* invalidate the context handle */

   (void)kg_delete_ctx_id(*context_handle);

   /* free all the context state */

   ctx = (gss_ctx_id_t) *context_handle;

   if (ctx->enc.processed)
      krb5_finish_key(context, &ctx->enc.eblock);
   krb5_free_keyblock(context, ctx->enc.key);

   if (ctx->seq.processed)
      krb5_finish_key(context, &ctx->seq.eblock);

   krb5_free_principal(context, ctx->here);
   krb5_free_principal(context, ctx->there);
   krb5_free_keyblock(context, ctx->subkey);

   if (ctx->auth_context)
       krb5_auth_con_free(context, ctx->auth_context);
   
   xfree(ctx);

   /* zero the handle itself */

   *context_handle = GSS_C_NO_CONTEXT;

   *minor_status = 0;
   return(GSS_S_COMPLETE);
}
