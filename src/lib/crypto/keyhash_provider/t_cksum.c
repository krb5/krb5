/*
 * lib/crypto/md5/t_cksum.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */

/*
 * t_cksum.c - Test checksum and checksum compatability for rsa-md[4,5]-des
 */

#include "k5-int.h"

#define MD5_K5BETA_COMPAT
#define MD4_K5BETA_COMPAT

#if	MD == 4
extern struct krb5_keyhash_provider krb5int_keyhash_md4des;
#define khp krb5int_keyhash_md4des
#endif

#if	MD == 5
extern struct krb5_keyhash_provider krb5int_keyhash_md5des;
#define khp krb5int_keyhash_md5des
#endif

static void
print_checksum(text, number, message, checksum)
     char	*text;
     int	number;
     char	*message;
     krb5_data	*checksum;
{
  int i;

  printf("%s MD%d checksum(\"%s\") = ", text, number, message);
  for (i=0; i<checksum->length; i++)
    printf("%02x", (unsigned char) checksum->data[i]);
  printf("\n");
}

/*
 * Test the checksum verification of Old Style (tm) and correct RSA-MD[4,5]-DES
 * checksums.
 */

krb5_octet testkey[8] = { 0x45, 0x01, 0x49, 0x61, 0x58, 0x19, 0x1a, 0x3d };

int
main(argc, argv)
     int argc;
     char **argv;
{
  int 			msgindex;
  krb5_boolean		valid;
  size_t		length;
  krb5_keyblock		keyblock;
  krb5_error_code	kret=0;
  krb5_data		plaintext, newstyle_checksum;

  /* this is a terrible seed, but that's ok for the test. */

  plaintext.length = 8;
  plaintext.data = (char *) testkey;

  krb5_c_random_seed(/* XXX */ 0, &plaintext);

  keyblock.enctype = ENCTYPE_DES_CBC_CRC;
  keyblock.length = sizeof(testkey);
  keyblock.contents = testkey;

  (*(khp.hash_size))(&length);

  newstyle_checksum.length = length;

  if (!(newstyle_checksum.data = (char *)
	malloc((unsigned) newstyle_checksum.length))) {
    printf("cannot get memory for new style checksum\n");
    return(ENOMEM);
  }
  for (msgindex = 1; msgindex < argc; msgindex++) {
    plaintext.length = strlen(argv[msgindex]);
    plaintext.data = argv[msgindex];

    if ((kret = (*(khp.hash))(&keyblock, 0, 0, &plaintext, &newstyle_checksum))) {
      printf("krb5_calculate_checksum choked with %d\n", kret);
      break;
    }
    print_checksum("correct", MD, argv[msgindex], &newstyle_checksum);

    if ((kret = (*(khp.verify))(&keyblock, 0, 0, &plaintext, &newstyle_checksum,
				&valid))) {
      printf("verify on new checksum choked with %d\n", kret);
      break;
    }
    if (!valid) {
      printf("verify on new checksum failed\n");
      break;
    }
    printf("Verify succeeded for \"%s\"\n", argv[msgindex]);

    newstyle_checksum.data[0]++;
    if ((kret = (*(khp.verify))(&keyblock, 0, 0, &plaintext, &newstyle_checksum,
				&valid))) {
      printf("verify on new checksum choked with %d\n", kret);
      break;
    }
    if (valid) {
      printf("verify on new checksum succeeded, but shouldn't have\n");
      break;
    }
    printf("Verify of bad checksum OK for \"%s\"\n", argv[msgindex]);
    kret = 0;
  }
  free(newstyle_checksum.data);
  if (!kret)
    printf("%d tests passed successfully for MD%d checksum\n", argc-1, MD);
  return(kret);
}
