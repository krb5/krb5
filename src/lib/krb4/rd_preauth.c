/* rd_preauth.c */
/* part of Cygnus Network Security */
/* Copyright 1994 Cygnus Support */
/*
 * Permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation.
 * Cygnus Support makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "krb.h"
#include "krb_db.h"
#include "prot.h"
#include "des.h"
#include "krb4int.h"
#include <string.h>

/* #define      KERB_ERR_PREAUTH_SHORT		11 */
/* #define	KERB_ERR_PREAUTH_MISMATCH	12 */


int
krb_rd_preauth(pkt, preauth_p, preauth_len, auth_pr, key)
    KTEXT pkt;
    char *preauth_p;
    int preauth_len;
    Principal *auth_pr;
    des_cblock key;
{
    int st;
    char *name_p;

    name_p = auth_pr->name;
   
#ifndef NOENCRYPTION
    /* Decrypt preauth_p using key as the key and initialization vector. */
    /* check preauth_len */
    if ((((strlen(name_p) + 1) / 8) + 1) * 8 != preauth_len)
	return KERB_ERR_PREAUTH_SHORT;
    else {
	des_key_schedule key_s;

	if (des_key_sched(key, key_s)) {
	    return 1;
	}
	des_pcbc_encrypt((des_cblock *)preauth_p, (des_cblock *)preauth_p,
			 (long)preauth_len, key_s, (des_cblock *)key, 
			 DES_DECRYPT);
	memset(key_s, 0, sizeof(key_s));
    }
#endif /* R3_NO_MODIFICATIONS */

    /* since the preauth data has the trailing 0, this just works */
    st = strcmp(preauth_p, name_p);
    if (st)
	return KERB_ERR_PREAUTH_MISMATCH;
    return 0;
}
