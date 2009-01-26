/*
 * lib/crypto/keyhash_provider/md5_hmac.c
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
 * Implementation of Microsoft KERB_CHECKSUM_MD5_HMAC
 */

#include "k5-int.h"
#include "keyhash_provider.h"
#include "arcfour-int.h"
#include "rsa-md5.h"
#include "hash_provider.h"

static  krb5_error_code
k5_md5_hmac_hash (const krb5_keyblock *key, krb5_keyusage usage,
		  const krb5_data *iv,
		  const krb5_data *input, krb5_data *output)
{
  krb5_keyusage ms_usage;
  krb5_MD5_CTX ctx;
  unsigned char t[4];
  krb5_data ds;

  krb5_MD5Init(&ctx);

  ms_usage = krb5int_arcfour_translate_usage (usage);
  store_32_le(ms_usage, t);
  krb5_MD5Update(&ctx, t, sizeof(t));
  krb5_MD5Update(&ctx, (unsigned char *)input->data, input->length);
  krb5_MD5Final(&ctx);

  ds.magic = KV5M_DATA;
  ds.length = 16;
  ds.data = (char *)ctx.digest;

  return krb5_hmac ( &krb5int_hash_md5, key, 1, &ds, output);
}

const struct krb5_keyhash_provider krb5int_keyhash_md5_hmac = {
  16,
  k5_md5_hmac_hash,
  NULL /*checksum  again*/
};

