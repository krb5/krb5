/*
main * lib/crypto/t_encrypt.c
 *
 * Copyright2001 by the Massachusetts Institute of Technology.
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
  0
};

#define test(msg, exp) \
printf ("%s: . . . ", msg); \
retval = (exp);\
if( retval) { \
  printf( "Failed: %s\n", error_message(retval)); \
  abort(); \
} else printf ("OK\n");
  
int
main ()
{
  krb5_context context = 0;
  krb5_data  in, out, check, state;
  int i;
  size_t len;
  krb5_enc_data enc_out;
  krb5_error_code retval;
  krb5_keyblock *key;
  in.data = "This is a test.\n";
  in.length = strlen (in.data);

  test ("Seeding random number generator",
	krb5_c_random_seed (context, &in));
  out.data = malloc(2048);
  check.data = malloc(2048);
  out.length = 2048;
  check.length = 2048;
  for (i = 0; interesting_enctypes[i]; i++) {
    krb5_enctype enctype = interesting_enctypes [i];
    printf ("Testing enctype %d\n", enctype);
    test ("Initializing a keyblock",
	  krb5_init_keyblock (context, enctype, 0, &key));
    test ("Generating random key",
	  krb5_c_make_random_key (context, enctype, key));
    enc_out.ciphertext.data = out.data;
    enc_out.ciphertext.length = out.length;
    /* We use an intermediate `len' because size_t may be different size 
       than `int' */
    krb5_c_encrypt_length (context, key->enctype, in.length, &len);
    enc_out.ciphertext.length = len;
    test ("Encrypting",
	  krb5_c_encrypt (context, key, 7, 0, &in, &enc_out));
    test ("Decrypting",
	  krb5_c_decrypt (context, key, 7, 0, &enc_out, &check));
    test ("init_state",
	  krb5_c_init_state (context, key, 7, &state));
        test ("Encrypting with state",
	  krb5_c_encrypt (context, key, 7, &state, &in, &enc_out));
    test ("Decrypting",
	  krb5_c_decrypt (context, key, 7, 0, &enc_out, &check));
    test ("free_state",
	  krb5_c_free_state (context, key, &state));
    krb5_free_keyblock (context, key);
  }

  free(out.data);
  free(check.data);
  return 0;
}

	
