/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * MIT Data Encryption Standard software implementation declarations.
 */

#include <krb5/mit-copyright.h>

#ifndef __MIT_DES__
#define __MIT_DES__

typedef octet des_cblock[8];	/* crypto-block size */

/* Key schedule--used internally by DES routines to gain some speed */
typedef struct des_ks_struct { des_cblock _; } des_key_schedule[16];

#define DES_KEY_SZ 	(8*sizeof(octet))

/* the first byte of the key is already in the keyblock */
#define DES_KEYBLOCK_SZ	(sizeof(krb5_keyblock)+sizeof(des_cblock)-sizeof(octet))

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#endif /* __MIT_DES__ */
