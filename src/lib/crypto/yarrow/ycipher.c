/*
 * lib/crypto/yarrow/ycipher.c
 *
 * Copyright (C) 2001 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 *  Routines  to implement krb5 cipher operations.
 */
#include "k5-int.h"
#include "yarrow.h"
#include "ycipher.h"
#include "enc_provider.h"
#include "assert.h"

int
krb5int_yarrow_cipher_init
(CIPHER_CTX *ctx,
 unsigned const char * key)
{
  size_t keybytes, keylength;
  const struct krb5_enc_provider *enc = &yarrow_enc_provider;
  krb5_error_code ret;
  krb5_data randombits;
  keybytes = enc->keybytes;
  keylength = enc->keylength;
  assert (keybytes == CIPHER_KEY_SIZE);
  if (ctx->key.contents) {
    memset (ctx->key.contents, 0, ctx->key.length);
    free (ctx->key.contents);
  }
  ctx->key.contents = (void *) malloc  (keylength);
  ctx->key.length = keylength;
  if (ctx->key.contents == NULL)
    return (YARROW_NOMEM);
  randombits.data = (char *) key;
  randombits.length = keybytes;
  ret = enc->make_key (&randombits, &ctx->key);
  if (ret) {
    memset (ctx->key.contents, 0, ctx->key.length);
    free(ctx->key.contents);
    ctx->key.contents = NULL;
    return (YARROW_FAIL);
  }
  return (YARROW_OK);
}

int krb5int_yarrow_cipher_encrypt_block
(CIPHER_CTX *ctx, const unsigned char *in,
 unsigned char *out)
{
  krb5_error_code ret;
  krb5_data ind, outd;
  const struct krb5_enc_provider *enc = &yarrow_enc_provider;
  ind.data = (char *) in;
  ind.length = CIPHER_BLOCK_SIZE;
  outd.data = out;
  outd.length = CIPHER_BLOCK_SIZE;
  ret = enc->encrypt (&ctx->key, 0, &ind, &outd);
  if (ret)
    return YARROW_FAIL;
  return YARROW_OK;
}

void
krb5int_yarrow_cipher_final
(CIPHER_CTX *ctx)

{
 if (ctx->key.contents) {
    memset (ctx->key.contents, 0, ctx->key.length);
    free (ctx->key.contents);
  }
  ctx->key.contents = 0;
  ctx->key.length = 0;
}
