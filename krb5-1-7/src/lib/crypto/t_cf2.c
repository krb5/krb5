/*
 * lib/crypto/t_cf2.c
 *
 * Copyright (C) 2004, 2009 by the Massachusetts Institute of Technology.
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
 * This file contains tests for theKRB-FX-CF2 code in Kerberos, based
 *on the PRF regression tests.  It reads an input file, and writes an
 *output file.  It is assumed that the output file will be diffed
 *against expected output to see whether regression tests pass.  The
 *input file is a very primitive format.
 *First line: enctype
 *second line: key to pass to string2key; also used as salt
 *Third line: second key to pass to string2key
 *fourth line: pepper1
 *fifth line:  pepper2
 *scanf is used to read the file, so interior spaces are not permitted.  The program outputs the hex bytes of the key.
 */
#include <krb5.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main () {
  char pepper1[1024], pepper2[1024];
  krb5_keyblock *k1 = NULL, *k2 = NULL, *out = NULL;
  krb5_data s2k;
  unsigned int i;
  while (1) {
    krb5_enctype enctype;
    char s[1025];

    if (scanf( "%d", &enctype) == EOF)
      break;
    if (scanf("%1024s", &s[0]) == EOF)
      break;
    assert (krb5_init_keyblock(0, enctype, 0, &k1) == 0);
    s2k.data = &s[0];
    s2k.length = strlen(s);
    assert(krb5_c_string_to_key (0, enctype, &s2k, &s2k, k1) == 0);
    if (scanf("%1024s", &s[0]) == EOF)
      break;
    assert (krb5_init_keyblock(0, enctype, 0, &k2) == 0);
    s2k.data = &s[0];
    s2k.length = strlen(s);
    assert(krb5_c_string_to_key (0, enctype, &s2k, &s2k, k2) == 0);
    if (scanf("%1024s %1024s", pepper1, pepper2) == EOF)
      break;
    assert(krb5_c_fx_cf2_simple(0, k1, pepper1,
				k2, pepper2, &out) ==0);
    i = out->length;
    for (; i > 0; i--) {
      printf ("%02x",
	      (unsigned int) ((unsigned char) out->contents[out->length-i]));
    }
    printf ("\n");

    krb5_free_keyblock(0,out);
    out = NULL;
	  
    krb5_free_keyblock(0, k1);
    k1 = NULL;
    krb5_free_keyblock(0, k2);
    k2 =  NULL;
  }

  return (0);
}
