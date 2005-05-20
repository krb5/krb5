/*
 * lib/crypto/dk/prf.c
 *
 * Copyright (C) 2004 by the Massachusetts Institute of Technology.
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
 *simplified profile enctypes.
 */

#include "k5-int.h"
#include "dk.h"

krb5_error_code
krb5int_dk_prf (const struct krb5_enc_provider *enc,
		const struct krb5_hash_provider *hash,
		const krb5_keyblock *key,
		const krb5_data *in, krb5_data *out)
{
  krb5_data tmp;
  krb5_data prfconst;
  krb5_keyblock *kp = NULL;
  krb5_error_code ret = 0;
  
  prfconst.data = (char *) "prf";
  prfconst.length = 3;
  tmp.length = hash->hashsize;
  tmp.data = malloc(hash->hashsize);
  if (tmp.data == NULL)
    return ENOMEM;
  hash->hash(1, in, &tmp);
  tmp.length = (tmp.length/enc->block_size)*enc->block_size; /*truncate to block size*/
  ret = krb5int_c_init_keyblock(0, key->enctype,
			   key->length, &kp);
    if (ret == 0)
      ret = krb5_derive_key(enc, key, kp, &prfconst);
  if (ret == 0)
    ret = enc->encrypt(kp, NULL, &tmp, out);
      if (kp)
	krb5int_c_free_keyblock(0, kp);
  free (tmp.data);
  return ret;
}
