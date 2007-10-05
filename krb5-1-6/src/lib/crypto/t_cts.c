/*
 * lib/crypto/vectors.c
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.
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
 * Test vectors for crypto code, matching data submitted for inclusion
 * with RFC1510bis.
 *
 * N.B.: Doesn't compile -- this file uses some routines internal to our
 * crypto library which are declared "static" and thus aren't accessible
 * without modifying the other sources.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "hash_provider.h"

#define ASIZE(ARRAY) (sizeof(ARRAY)/sizeof(ARRAY[0]))

const char *whoami;

static void printhex (size_t len, const char *p)
{
    while (len--)
	printf ("%02x", 0xff & *p++);
}

static void printstringhex (const char *p) { printhex (strlen (p), p); }

static void printdata (krb5_data *d) { printhex (d->length, d->data); }

static void printkey (krb5_keyblock *k) { printhex (k->length, k->contents); }


#define JURISIC "Juri\305\241i\304\207" /* hi Miro */
#define ESZETT "\303\237"
#define GCLEF  "\360\235\204\236" /* outside BMP, woo hoo!  */

static void
keyToData (krb5_keyblock *k, krb5_data *d)
{
    d->length = k->length;
    d->data = k->contents;
}

void check_error (int r, int line) {
    if (r != 0) {
	fprintf (stderr, "%s:%d: %s\n", __FILE__, line,
		 error_message (r));
	exit (1);
    }
}
#define CHECK check_error(r, __LINE__)

extern struct krb5_enc_provider krb5int_enc_des3;
struct krb5_enc_provider *enc = &krb5int_enc_des3;
extern struct krb5_enc_provider krb5int_enc_aes128, krb5int_enc_aes256;

static void printd (const char *descr, krb5_data *d) {
    int i, j;
    const int r = 16;

    printf("%s:", descr);

    for (i = 0; i < d->length; i += r) {
	printf("\n  %04x: ", i);
	for (j = i; j < i + r && j < d->length; j++)
	    printf(" %02x", 0xff & d->data[j]);
#ifdef SHOW_TEXT
	for (; j < i + r; j++)
	    printf("   ");
	printf("   ");
	for (j = i; j < i + r && j < d->length; j++) {
	    int c = 0xff & d->data[j];
	    printf("%c", isprint(c) ? c : '.');
	}
#endif
    }
    printf("\n");
}
static void printk(const char *descr, krb5_keyblock *k) {
    krb5_data d;
    d.data = k->contents;
    d.length = k->length;
    printd(descr, &d);
}

static void test_cts()
{
    static const char input[4*16] =
	"I would like the General Gau's Chicken, please, and wonton soup.";
    static const unsigned char aeskey[16] = "chicken teriyaki";
    static const int lengths[] = { 17, 31, 32, 47, 48, 64 };
    extern krb5_error_code krb5int_aes_encrypt(const krb5_keyblock *,
					       const krb5_data *,
					       const krb5_data *,
					       krb5_data *);

    int i;
    char outbuf[64], encivbuf[16], decivbuf[16], outbuf2[64];
    krb5_data in, out, enciv, deciv, out2;
    krb5_keyblock key;
    krb5_error_code err;

    in.data = input;
    out.data = outbuf;
    out2.data = outbuf2;
    enciv.length = deciv.length = 16;
    enciv.data = encivbuf;
    deciv.data = decivbuf;
    key.contents = aeskey;
    key.length = 16;

    memset(enciv.data, 0, 16);
    printk("AES 128-bit key", &key);
    for (i = 0; i < sizeof(lengths)/sizeof(lengths[0]); i++) {
    memset(enciv.data, 0, 16);
    memset(deciv.data, 0, 16);

	printf("\n");
	in.length = out.length = lengths[i];
	printd("IV", &enciv);
	err = krb5int_aes_encrypt(&key, &enciv, &in, &out);
	if (err) {
	    printf("error %ld from krb5int_aes_encrypt\n", (long)err);
	    exit(1);
	}
	printd("Input", &in);
	printd("Output", &out);
	printd("Next IV", &enciv);
	out2.length = out.length;
	err = krb5int_aes_decrypt(&key, &deciv, &out, &out2);
	if (err) {
	    printf("error %ld from krb5int_aes_decrypt\n", (long)err);
	    exit(1);
	}
	if (out2.length != in.length
	    || memcmp(in.data, out2.data, in.length)) {
	    printd("Decryption result DOESN'T MATCH", &out2);
	    exit(1);
	}
	if (memcmp(enciv.data, deciv.data, 16)) {
	    printd("Decryption IV result DOESN'T MATCH", &deciv);
	    exit(1);
	}
    }
}

int main (int argc, char **argv)
{
    whoami = argv[0];
    test_cts();
    return 0;
}
