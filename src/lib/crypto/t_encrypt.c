/*
 * lib/crypto/t_encrypt.c
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
  
int main () {
  krb5_context context ;
  krb5_data  in, out, check;
  int i;
  krb5_enc_data enc_out;
  krb5_error_code retval;
  krb5_keyblock key;
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
    test ("Generating random key",
	  krb5_c_make_random_key (context, enctype, &key));
    enc_out.ciphertext = out;
    krb5_c_encrypt_length (context, key.enctype, in.length, &enc_out.ciphertext.length);
    test ("Encrypting",
	  krb5_c_encrypt (context, &key, 7, 0, &in, &enc_out));
    test ("Decrypting",
	  krb5_c_decrypt (context, &key, 7, 0, &enc_out, &check));
  }
  return 0;
}

	
