/*
 * lib/crypto/t_encrypt.c
 *
 * Copyright 2001, 2008 by the Massachusetts Institute of Technology.
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
 * <<< Description >>>
 */
/* 
 * Some black-box tests of crypto systems.  Make sure that we can decrypt things we encrypt, etc.
 */

#include "k5-int.h"
#include "etypes.h"
#include <stdio.h>

/* What enctypes should we test?*/
krb5_enctype interesting_enctypes[] = {
  ENCTYPE_DES_CBC_CRC,
  ENCTYPE_DES_CBC_MD4,
  ENCTYPE_DES_CBC_MD5,
  ENCTYPE_DES3_CBC_SHA1,
  ENCTYPE_ARCFOUR_HMAC,
  ENCTYPE_ARCFOUR_HMAC_EXP,
  ENCTYPE_AES256_CTS_HMAC_SHA1_96,
  ENCTYPE_AES128_CTS_HMAC_SHA1_96,
  0
};

static void
test(const char *msg, krb5_error_code retval)
{
    printf("%s: . . . ", msg);
    if (retval) {
	printf("Failed: %s\n", error_message(retval));
	abort();
    } else
	printf("OK\n");
}

static int compare_results(krb5_data *d1, krb5_data *d2)
{
    if (d1->length != d2->length) {
	/* Decryption can leave a little trailing cruft.
	   For the current cryptosystems, this can be up to 7 bytes.  */
	if (d1->length + 8 <= d2->length)
	    return EINVAL;
	if (d1->length > d2->length)
	    return EINVAL;
    }
    if (memcmp(d1->data, d2->data, d1->length)) {
	return EINVAL;
    }
    return 0;
}

int
main ()
{
  krb5_context context = 0;
  krb5_data  in, in2, out, out2, check, check2, state;
  krb5_crypto_iov iov[5];
  int i;
  size_t len;
  krb5_enc_data enc_out, enc_out2;
  krb5_error_code retval;
  krb5_keyblock *key;

  memset(iov, 0, sizeof(iov));

  in.data = "This is a test.\n";
  in.length = strlen (in.data);
  in2.data = "This is another test.\n";
  in2.length = strlen (in2.data);

  test ("Seeding random number generator",
	krb5_c_random_seed (context, &in));
  out.data = malloc(2048);
  out2.data = malloc(2048);
  check.data = malloc(2048);
  check2.data = malloc(2048);
  if (out.data == NULL || out2.data == NULL
      || check.data == NULL || check2.data == NULL)
      abort();
  out.length = 2048;
  out2.length = 2048;
  check.length = 2048;
  check2.length = 2048;
  for (i = 0; interesting_enctypes[i]; i++) {
    krb5_enctype enctype = interesting_enctypes [i];
    printf ("Testing enctype %d\n", enctype);
    test ("Initializing a keyblock",
	  krb5_init_keyblock (context, enctype, 0, &key));
    test ("Generating random key",
	  krb5_c_make_random_key (context, enctype, key));
    enc_out.ciphertext = out;
    enc_out2.ciphertext = out2;
    /* We use an intermediate `len' because size_t may be different size 
       than `int' */
    krb5_c_encrypt_length (context, key->enctype, in.length, &len);
    enc_out.ciphertext.length = len;
    test ("Encrypting",
	  krb5_c_encrypt (context, key, 7, 0, &in, &enc_out));
    test ("Decrypting",
	  krb5_c_decrypt (context, key, 7, 0, &enc_out, &check));
    test ("Comparing", compare_results (&in, &check));
    if ( krb5_c_crypto_length(context, key->enctype, KRB5_CRYPTO_TYPE_HEADER, &len) == 0 ){
	/* We support iov/aead*/
	int j, pos;
	krb5_data signdata;
	signdata.data = (char *) "This should be signed";
	signdata.length = strlen(signdata.data);
	iov[0].flags= KRB5_CRYPTO_TYPE_STREAM;
	iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
	iov[0].data = enc_out.ciphertext;
	iov[1].data = out;
	test("IOV stream decrypting",
	     krb5_c_decrypt_iov( context, key, 7, 0, iov, 2));
	test("Comparing results",
	     compare_results(&in, &iov[1].data));
	iov[0].flags = KRB5_CRYPTO_TYPE_HEADER;
	iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
	iov[1].data = in; /*We'll need to copy memory before encrypt*/
	iov[2].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
	iov[2].data = signdata;
	iov[3].flags = KRB5_CRYPTO_TYPE_PADDING;
	iov[4].flags = KRB5_CRYPTO_TYPE_TRAILER;
	test("Setting up iov lengths",
	     krb5_c_crypto_length_iov(context, key->enctype, iov, 5));
	for (j=0,pos=0; j <= 4; j++ ){
	    if (iov[j].flags == KRB5_CRYPTO_TYPE_SIGN_ONLY)
		continue;
	    iov[j].data.data = &out.data[pos];
	    pos += iov[j].data.length;
	}
	assert (iov[1].data.length == in.length);
	memcpy(iov[1].data.data, in.data, in.length);
	test("iov encrypting",
	     krb5_c_encrypt_iov(context, key, 7, 0, iov, 5));
	assert(iov[1].data.length == in.length);
	test("iov decrypting",
	     krb5_c_decrypt_iov(context, key, 7, 0, iov, 5));
	test("Comparing results",
	     compare_results(&in, &iov[1].data));
		       
    }
    enc_out.ciphertext.length = out.length;
    check.length = 2048;
    test ("init_state",
	  krb5_c_init_state (context, key, 7, &state));
    test ("Encrypting with state",
	  krb5_c_encrypt (context, key, 7, &state, &in, &enc_out));
    test ("Encrypting again with state",
	  krb5_c_encrypt (context, key, 7, &state, &in2, &enc_out2));
    test ("free_state",
	  krb5_c_free_state (context, key, &state));
    test ("init_state",
	  krb5_c_init_state (context, key, 7, &state));
    test ("Decrypting with state",
	  krb5_c_decrypt (context, key, 7, &state, &enc_out, &check));
    test ("Decrypting again with state",
	  krb5_c_decrypt (context, key, 7, &state, &enc_out2, &check2));
    test ("free_state",
	  krb5_c_free_state (context, key, &state));
    test ("Comparing",
	  compare_results (&in, &check));
    test ("Comparing",
	  compare_results (&in2, &check2));
    krb5_free_keyblock (context, key);
  }

  /* Test the RC4 decrypt fallback from key usage 9 to 8. */
  test ("Initializing an RC4 keyblock",
	krb5_init_keyblock (context, ENCTYPE_ARCFOUR_HMAC, 0, &key));
  test ("Generating random RC4 key",
	krb5_c_make_random_key (context, ENCTYPE_ARCFOUR_HMAC, key));
  enc_out.ciphertext = out;
  krb5_c_encrypt_length (context, key->enctype, in.length, &len);
  enc_out.ciphertext.length = len;
  check.length = 2048;
  test ("Encrypting with RC4 key usage 8",
	krb5_c_encrypt (context, key, 8, 0, &in, &enc_out));
  test ("Decrypting with RC4 key usage 9",
	krb5_c_decrypt (context, key, 9, 0, &enc_out, &check));
  test ("Comparing", compare_results (&in, &check));

  free(out.data);
  free(out2.data);
  free(check.data);
  free(check2.data);
  return 0;
}

	
