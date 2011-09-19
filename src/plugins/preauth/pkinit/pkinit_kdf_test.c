/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* prototype/prototype.c */
/*
 * Copyright (C) 2011 by the Massachusetts Institute of Technology.
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
 */

/*
 * pkinit_kdf_test.c -- Test to verify the correctness of the function
 * pkinit_alg_agility_kdf() in pkinit_crypto_openssl, which implements
 * the Key Derivation Function from the PKInit Algorithm Agility
 * document, currently draft-ietf-krb-wg-pkinit-alg-agility-04.txt.
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>

#include "k5-platform.h"

#include "pkinit_crypto_openssl.h"

/**
 * Initialize a krb5_data from @a s, a constant string. Note @a s is evaluated
 * multiple times; this is acceptable for constants.
 */
#define DATA_FROM_STRING(s) \
    {0, sizeof(s)-1, (char *) s}


/* values from the test vector in the pkinit-alg-agility draft */
int secret_len = 256;
char twenty_as[10];
char eighteen_bs[9] ;
char party_u_name [] = "lha@SU.SE";
char party_v_name [] = "krbtgt/SU.SE@SU.SE";
int enctype_value = 18;
krb5_octet key_hex [] =
  {0xC7, 0x62, 0x89, 0xEC, 0x4B, 0x28, 0xA6, 0x91,
   0xFF, 0xCE, 0x80, 0xBB, 0xB7, 0xEC, 0x82, 0x41,
   0x52, 0x3F, 0x99, 0xB1, 0x90, 0xCF, 0x2D, 0x34,
   0x8F, 0x54, 0xA8, 0x65, 0x81, 0x2C, 0x32, 0x73};
const krb5_data lha_data = DATA_FROM_STRING("lha");
const krb5_principal_data ticket_server = {
    0, /*magic*/
    DATA_FROM_STRING("SU.SE"),
    (krb5_data *) &lha_data,
    1, 1};
const krb5_ticket test_ticket = {
    KV5M_TICKET,
    (krb5_principal) &ticket_server,
    {0, /*magic*/
     18,
     0,
     DATA_FROM_STRING("hejhej") },
    NULL};



int
main (int argc,
      char  **argv)
{
    /* arguments for calls to pkinit_alg_agility_kdf() */
    krb5_context context = 0;
    krb5_octet_data secret;
    krb5_algorithm_identifier alg_id;
    krb5_enctype enctype = enctype_value;
    krb5_octet_data as_req;
    krb5_octet_data pk_as_rep;
    krb5_keyblock key_block;

    /* other local variables */
    int retval = 0;
    int max_keylen = 2048;
    krb5_principal u_principal = NULL;
    krb5_principal v_principal = NULL;
    krb5_keyblock *key_block_ptr = &key_block;

    /* initialize variables that get malloc'ed, so cleanup is safe */
    krb5_init_context (&context);
    memset (&alg_id, 0, sizeof(alg_id));
    memset (&as_req, 0, sizeof(as_req));
    memset (&pk_as_rep, 0, sizeof(pk_as_rep));
    memset (&key_block, 0, sizeof(key_block));

    /* set up algorithm id */
    alg_id.algorithm.data = (unsigned char *) &krb5_pkinit_sha1_oid;
    alg_id.algorithm.length = krb5_pkinit_sha1_oid_len;

    /* set up a 256-byte, ALL-ZEROS secret */
    if (NULL == (secret.data = malloc(secret_len))) {
        printf("ERROR in pkinit_kdf_test: Memory allocation failed.");
        retval = ENOMEM;
        goto cleanup;
    }
    secret.length = secret_len;
    memset(secret.data, 0, secret_len);

    /* set-up the partyUInfo and partyVInfo principals */
    if ((0 != (retval = krb5_parse_name(context, party_u_name,
					&u_principal)))
	(0 != (retval = krb5_parse_name(context, party_v_name,
					&v_principal)))) {
      printf("ERROR in pkinit_kdf_test: Error parsing names, retval = %d",
	     retval);
      goto cleanup;
    }

    /* set-up the as_req and and pk_as_rep data */
    memset(twenty_as, 0xaa, sizeof(twenty_as));
           memset(eighteen_bs, 0xbb, sizeof(eighteen_bs));
    as_req.length = sizeof(twenty_as);
    as_req.data = (unsigned char *)&twenty_as;

    pk_as_rep.length = sizeof(eighteen_bs);
    pk_as_rep.data = (unsigned char *)&eighteen_bs;

    /* set-up the key_block */
    if (0 != (retval = krb5_init_keyblock(context, enctype, max_keylen,
                                          &key_block_ptr))) {
	  printf("ERROR in pkinit_kdf_test: can't init keybloc, retval = %d",
		 retval);
	  goto cleanup;

	}

    /* call krb5_pkinit_alg_agility_kdf() with test vector values*/
    if (0 != (retval = pkinit_alg_agility_kdf(context, &secret, &alg_id.algorithm,
					      u_principal, v_principal,
					      enctype, &as_req, &pk_as_rep,
					      &test_ticket, &key_block))) {
        printf("ERROR in pkinit_kdf_test: kdf call failed, retval = %d",
	       retval);
	goto cleanup;
    }

    /* compare key to expected key value */

    if ((key_block.length == sizeof(key_hex)) &&
            (0 == memcmp(key_block.contents, key_hex, key_block.length))) {
            printf("SUCCESS: Correct key value generated!");
            retval = 0;
        }
        else {
            printf("FAILURE: Incorrect key value generated!");
            retval = 1;
        }

    cleanup:
	/* release all allocated resources, whether good or bad return */
	if (secret.data)
	  free(secret.data);
	if (u_principal)
	  free(u_principal);
	if (v_principal)
	  free(v_principal);
		krb5_free_keyblock_contents(context, &key_block);
	exit(retval);
}
