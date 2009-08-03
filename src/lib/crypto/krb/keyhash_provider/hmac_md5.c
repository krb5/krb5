/*
 * lib/crypto/keyhash_provider/hmac_md5.c
 *
 * Copyright 2001, 2009 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Implementation of the Microsoft hmac-md5 checksum type.
 * Implemented based on draft-brezak-win2k-krb-rc4-hmac-03
 */

#include "k5-int.h"
#include "keyhash_provider.h"
#include "arcfour-int.h"
#include "rsa-md5.h"
#include "hash_provider.h"
#include "../aead.h"

static  krb5_error_code
k5_hmac_md5_hash (const krb5_keyblock *key, krb5_keyusage usage,
		  const krb5_data *iv,
		  const krb5_data *input, krb5_data *output)
{
  krb5_keyusage ms_usage;
  krb5_error_code ret;
  krb5_keyblock ks;
  krb5_data ds, ks_constant, md5tmp;
  krb5_MD5_CTX ctx;
  char t[4];
  

  ds.length = key->length;
  ks.length = key->length;
  ds.data = malloc(ds.length);
  if (ds.data == NULL)
    return ENOMEM;
  ks.contents = (void *) ds.data;

  ks_constant.data = "signaturekey";
  ks_constant.length = strlen(ks_constant.data)+1; /* Including null*/

  ret = krb5_hmac( &krb5int_hash_md5, key, 1,
		   &ks_constant, &ds);
  if (ret)
    goto cleanup;

  krb5_MD5Init (&ctx);
  ms_usage = krb5int_arcfour_translate_usage (usage);
  store_32_le(ms_usage, t);
  krb5_MD5Update (&ctx, (unsigned char * ) &t, 4);
  krb5_MD5Update (&ctx, (unsigned char *) input-> data,
		  (unsigned int) input->length );
  krb5_MD5Final(&ctx);
  md5tmp.data = (void *) ctx.digest;
  md5tmp.length = 16;
  ret = krb5_hmac ( &krb5int_hash_md5, &ks, 1, &md5tmp,
		    output);

    cleanup:
  memset(&ctx, 0, sizeof(ctx));
  memset (ks.contents, 0, ks.length);
  free (ks.contents);
  return ret;
}

static  krb5_error_code
k5_hmac_md5_hash_iov (const krb5_keyblock *key, krb5_keyusage usage,
		      const krb5_data *iv,
		      const krb5_crypto_iov *data, size_t num_data,
		      krb5_data *output)
{
  krb5_keyusage ms_usage;
  krb5_error_code ret;
  krb5_keyblock ks;
  krb5_data ds, ks_constant, md5tmp;
  krb5_MD5_CTX ctx;
  char t[4];
  size_t i;

  ds.length = key->length;
  ks.length = key->length;
  ds.data = malloc(ds.length);
  if (ds.data == NULL)
    return ENOMEM;
  ks.contents = (void *) ds.data;

  ks_constant.data = "signaturekey";
  ks_constant.length = strlen(ks_constant.data)+1; /* Including null*/

  ret = krb5_hmac( &krb5int_hash_md5, key, 1,
		   &ks_constant, &ds);
  if (ret)
    goto cleanup;

  krb5_MD5Init (&ctx);
  ms_usage = krb5int_arcfour_translate_usage (usage);
  store_32_le(ms_usage, t);
  krb5_MD5Update (&ctx, (unsigned char * ) &t, 4);
  for (i = 0; i < num_data; i++) {
    const krb5_crypto_iov *iov = &data[i];

    if (SIGN_IOV(iov))
      krb5_MD5Update (&ctx, (unsigned char *)iov->data.data,
		      (unsigned int)iov->data.length);
  }
  krb5_MD5Final(&ctx);
  md5tmp.data = (void *) ctx.digest;
  md5tmp.length = 16;
  ret = krb5_hmac ( &krb5int_hash_md5, &ks, 1, &md5tmp,
		    output);

    cleanup:
  memset(&ctx, 0, sizeof(ctx));
  memset (ks.contents, 0, ks.length);
  free (ks.contents);
  return ret;
}

const struct krb5_keyhash_provider krb5int_keyhash_hmac_md5 = {
  16,
  k5_hmac_md5_hash,
  NULL, /*checksum  again*/
  k5_hmac_md5_hash_iov,
  NULL  /*checksum  again */
};
