/*
 * lib/crypto/des/t_random.c
 *
 * Copyright 1996 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Test a DES implementation against known inputs & outputs
 */

#include "k5-int.h"
#include "des_int.h"
#include <stdio.h>
#include "com_err.h"

extern krb5_cryptosystem_entry mit_des_cryptosystem_entry;

char *progname;
int nflag = 2;
int vflag;
int mflag;
int zflag;
int pid;
int mit_des_debug;

krb5_data kdata;

unsigned char key2[8] = { 0x08,0x19,0x2a,0x3b,0x4c,0x5d,0x6e,0x7f };
unsigned char zerokey[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

void print_key(key)
	krb5_keyblock *key;
{
	int 	i;

	printf("key type: %d, length = %d, contents =", key->enctype,
	       key->length);
	for (i=0; i < key->length; i++) {
		printf(" %02x", key->contents[i]);
	}
	printf("\n");
}

/*
 * Can also add :
 * plaintext = 0, key = 0, cipher = 0x8ca64de9c1b123a7 (or is it a 1?)
 */

void
main(argc,argv)
    int argc;
    char *argv[];
{
    /* Local Declarations */
    krb5_context context;
    krb5_encrypt_block eblock;
    krb5_keyblock keyblock, *randkey;
    void *random_seed = 0;

#ifdef WINDOWS
    /* Set screen window buffer to infinite size -- MS default is tiny.  */
    _wsetscreenbuf (fileno (stdout), _WINBUFINF);
#endif

    /* do some initialisation */
    krb5_init_context(&context);

    krb5_use_enctype(context, &eblock, ENCTYPE_DES_CBC_CRC);
    keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    keyblock.length = sizeof(mit_des_cblock);

    keyblock.contents = key2;

    printf("init_random: ");
    print_key(&keyblock);
    krb5_init_random_key(context, &eblock, &keyblock, &random_seed);
    krb5_random_key(context, &eblock, random_seed, &randkey);
    print_key(randkey);
    krb5_free_keyblock(context, randkey);
    krb5_random_key(context, &eblock, random_seed, &randkey);
    print_key(randkey);
    krb5_free_keyblock(context, randkey);
    krb5_finish_random_key(context, &eblock, &random_seed);

    keyblock.contents = zerokey;

    printf("\n\ninit_random: ");
    print_key(&keyblock);

    krb5_init_random_key(context, &eblock, &keyblock, &random_seed);
    krb5_random_key(context, &eblock, random_seed, &randkey);
    print_key(randkey);
    krb5_free_keyblock(context, randkey);
    krb5_random_key(context, &eblock, random_seed, &randkey);
    print_key(randkey);
    krb5_free_keyblock(context, randkey);
    krb5_finish_random_key(context, &eblock, &random_seed);

    krb5_free_context(context);
}

