/*
 * lib/crypto/des/des_prf.c
 *
 * Copyright (C) 2004, 2009  by the Massachusetts Institute of Technology.
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
 * This file contains an implementation of the RFC 3961 PRF for
 * des-cbc-crc, des-cbc-md4, and des-cbc-md5 enctypes.
 */

#include "k5-int.h"
#include "../hash_provider/hash_provider.h"		/* XXX is this ok? */

krb5_error_code
krb5int_des_prf (const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		const krb5_keyblock *key,
		const krb5_data *in, krb5_data *out)
{
  krb5_data tmp;
  krb5_error_code ret = 0;

  hash = &krb5int_hash_md5;		/* MD5 is always used. */
  tmp.length = hash->hashsize;
  tmp.data = malloc(hash->hashsize);
  if (tmp.data == NULL)
    return ENOMEM;
  ret = hash->hash(1, in, &tmp);
  if (ret == 0)
      ret = enc->encrypt(key, NULL, &tmp, out);
  free(tmp.data);
  return ret;
}
