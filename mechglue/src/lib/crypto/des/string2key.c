/*
 * lib/crypto/des/des_s2k.c
 *
 * Copyright 2004 by the Massachusetts Institute of Technology.
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
 * Compute encryption key from salt and pass phrase.
 */

#include "k5-int.h"
#include "des_int.h"

krb5_error_code
mit_des_string_to_key_int (krb5_keyblock *key,
			   const krb5_data *pw, const krb5_data *salt)
{
    union {
	/* 8 "forward" bytes, 8 "reverse" bytes */
	unsigned char uc[16];
	krb5_ui_4 ui[4];
	mit_des_cblock cb;
    } temp;
    int i;
    krb5_ui_4 x, y, z;
    unsigned char *p;
    des_key_schedule sched;
    char *copy;
    size_t copylen;

    /* As long as the architecture is big-endian or little-endian, it
       doesn't matter which it is.  Think of it as reversing the
       bytes, and also reversing the bits within each byte.  But this
       current algorithm is dependent on having four 8-bit char values
       exactly overlay a 32-bit integral type.  */
    if (sizeof(temp.uc) != sizeof(temp.ui)
	|| (unsigned char)~0 != 0xFF
	|| (krb5_ui_4)~(krb5_ui_4)0 != 0xFFFFFFFF
	|| (temp.uc[0] = 1, temp.uc[1] = 2, temp.uc[2] = 3, temp.uc[3] = 4,
	    !(temp.ui[0] == 0x01020304
	      || temp.ui[0] == 0x04030201)))
	abort();
#define FETCH4(VAR, IDX)	VAR = temp.ui[IDX/4]
#define PUT4(VAR, IDX)		temp.ui[IDX/4] = VAR

    if (salt
	&& (salt->length == SALT_TYPE_AFS_LENGTH
	    /* XXX  Yuck!  Aren't we done with this yet?  */
	    || salt->length == (unsigned) -1)) {
	krb5_data afssalt;
	char *at;

	afssalt.data = salt->data;
	at = strchr(afssalt.data, '@');
	if (at) {
	    *at = 0;
	    afssalt.length = at - afssalt.data;
	} else
	    afssalt.length = strlen(afssalt.data);
	return mit_afs_string_to_key(key, pw, &afssalt);
    }

    copylen = pw->length + (salt ? salt->length : 0);
    /* Don't need NUL termination, at this point we're treating it as
       a byte array, not a string.  */
    copy = malloc(copylen);
    if (copy == NULL)
	return errno;
    memcpy(copy, pw->data, pw->length);
    if (salt)
	memcpy(copy + pw->length, salt->data, salt->length);

    memset(&temp, 0, sizeof(temp));
    p = temp.uc;
    /* Handle the fan-fold xor operation by splitting the data into
       forward and reverse sections, and combine them later, rather
       than having to do the reversal over and over again.  */
    for (i = 0; i < copylen; i++) {
	*p++ ^= copy[i];
	if (p == temp.uc+16) {
	    p = temp.uc;
#ifdef PRINT_TEST_VECTORS
	    {
		int j;
		printf("after %d input bytes:\nforward block:\t", i+1);
		for (j = 0; j < 8; j++)
		    printf(" %02x", temp.uc[j] & 0xff);
		printf("\nreverse block:\t");
		for (j = 8; j < 16; j++)
		    printf(" %02x", temp.uc[j] & 0xff);
		printf("\n");
	    }
#endif
	}
    }

#ifdef PRINT_TEST_VECTORS
    if (p != temp.uc) {
	int j;
	printf("at end, after %d input bytes:\nforward block:\t", i);
	for (j = 0; j < 8; j++)
	    printf(" %02x", temp.uc[j] & 0xff);
	printf("\nreverse block:\t");
	for (j = 8; j < 16; j++)
	    printf(" %02x", temp.uc[j] & 0xff);
	printf("\n");
    }
#endif
#if 0
    /* Algorithm described in Dr. Dobbs Journal 1983, reported in "bit
       twiddling hacks" web page collected by Sean Eron Anderson; see
       http://graphics.stanford.edu/~seander/bithacks.html for
       details.

       Avoids loops, uses 7*lg(N)=35 ops instead of 4*N=128 for the
       obvious mask, ior, shift, shift sequence of each 32-bit
       quantity.

       If we could rely on 64-bit math, another 7 ops would save us
       from having to do double the work.  */
#define REVERSE_STEP(VAR, SHIFT, MASK)			\
    VAR = ((VAR >> SHIFT) & MASK) | ((VAR << SHIFT) & (0xFFFFFFFFUL & ~MASK))
#define REVERSE(VAR)						\
    REVERSE_STEP (VAR, 1, 0x55555555UL); /* swap odd/even bits */	\
    REVERSE_STEP (VAR, 2, 0x33333333UL); /* swap bitpairs */		\
    REVERSE_STEP (VAR, 4, 0x0F0F0F0FUL); /* swap nibbles, etc */	\
    REVERSE_STEP (VAR, 8, 0x00FF00FFUL);				\
    REVERSE_STEP (VAR, 16, 0x0000FFFFUL);
#else /* shorter */
#define REVERSE(VAR)				\
    {						\
	krb5_ui_4 old = VAR, temp1 = 0;		\
	int j;					\
	for (j = 0; j < 32; j++) {		\
	    temp1 = (temp1 << 1) | (old & 1);	\
	    old >>= 1;				\
	}					\
	VAR = temp1;				\
    }
#endif

    FETCH4 (x, 8);
    FETCH4 (y, 12);
    /* Ignore high bits of each input byte.  */
    x &= 0x7F7F7F7F;
    y &= 0x7F7F7F7F;
    /* Reverse the bit strings -- after this, y is "before" x.  */
    REVERSE (x);
    REVERSE (y);
#ifdef PRINT_TEST_VECTORS
    {
	int j;
	union { unsigned char uc[4]; krb5_ui_4 ui; } t2;
	printf("after reversal, reversed block:\n\t\t");
	t2.ui = y;
	for (j = 0; j < 4; j++)
	    printf(" %02x", t2.uc[j] & 0xff);
	t2.ui = x;
	for (j = 0; j < 4; j++)
	    printf(" %02x", t2.uc[j] & 0xff);
	printf("\n");
    }
#endif
    /* Ignored bits are now at the bottom of each byte, where we'll
       put the parity bits.  Good.  */
    FETCH4 (z, 0);
    z &= 0x7F7F7F7F;
    /* Ignored bits for z are at the top of each byte; fix that.  */
    z <<= 1;
    /* Finish the fan-fold xor for these four bytes.  */
    z ^= y;
    PUT4 (z, 0);
    /* Now do the second four bytes.  */
    FETCH4 (z, 4);
    z &= 0x7F7F7F7F;
    /* Ignored bits for z are at the top of each byte; fix that.  */
    z <<= 1;
    /* Finish the fan-fold xor for these four bytes.  */
    z ^= x;
    PUT4 (z, 4);

#ifdef PRINT_TEST_VECTORS
    {
	int j;
	printf("after reversal, combined block:\n\t\t");
	for (j = 0; j < 8; j++)
	    printf(" %02x", temp.uc[j] & 0xff);
	printf("\n");
    }
#endif

#define FIXUP(K)					\
    (mit_des_fixup_key_parity(K),			\
     mit_des_is_weak_key(K) ? (K[7] ^= 0xF0) : 0)

    /* Now temp.cb is the temporary key, with invalid parity.  */
    FIXUP(temp.cb);

#ifdef PRINT_TEST_VECTORS
    {
	int j;
	printf("after fixing parity and weak keys:\n\t\t");
	for (j = 0; j < 8; j++)
	    printf(" %02x", temp.uc[j] & 0xff);
	printf("\n");
    }
#endif

    mit_des_key_sched(temp.cb, sched);
    mit_des_cbc_cksum(copy, temp.cb, copylen, sched, temp.cb);

    memset(copy, 0, copylen);
    free(copy);

#ifdef PRINT_TEST_VECTORS
    {
	int j;
	printf("cbc checksum:\n\t\t");
	for (j = 0; j < 8; j++)
	    printf(" %02x", temp.uc[j] & 0xff);
	printf("\n");
    }
#endif

    memset(sched, 0, sizeof(sched));
    FIXUP (temp.cb);

#ifdef PRINT_TEST_VECTORS
    {
	int j;
	printf("after fixing parity and weak keys:\n\t\t");
	for (j = 0; j < 8; j++)
	    printf(" %02x", temp.uc[j] & 0xff);
	printf("\n");
    }
#endif

    memcpy(key->contents, temp.cb, 8);
    memset(&temp, 0, sizeof(temp));

    return 0;
}
