/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/nss/des/des_keys.c - Key functions used by Kerberos code */
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

#include "crypto_int.h"

/*
 * des_fixup_key_parity: Forces odd parity per byte; parity is bits
 *                       8,16,...64 in des order, implies 0, 8, 16, ...
 *                       vax order.
 */
#define smask(step) ((1<<step)-1)
#define pstep(x,step) (((x)&smask(step))^(((x)>>step)&smask(step)))
#define parity_char(x) pstep(pstep(pstep((x),4),2),1)

void
k5_des_fixup_key_parity(unsigned char *keybits)
{
    unsigned int i;

    for (i = 0; i < 8; i++) {
        keybits[i] &= 0xfe;
        keybits[i] |= 1^parity_char(keybits[i]);
    }
}

/* The following are the weak DES keys: */
static const unsigned char weak[16][8] = {
    /* Weak keys */
    {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
    {0xfe,0xfe,0xfe,0xfe,0xfe,0xfe,0xfe,0xfe},
    {0x1f,0x1f,0x1f,0x1f,0x0e,0x0e,0x0e,0x0e},
    {0xe0,0xe0,0xe0,0xe0,0xf1,0xf1,0xf1,0xf1},

    /* Semi-weak */
    {0x01,0xfe,0x01,0xfe,0x01,0xfe,0x01,0xfe},
    {0xfe,0x01,0xfe,0x01,0xfe,0x01,0xfe,0x01},

    {0x1f,0xe0,0x1f,0xe0,0x0e,0xf1,0x0e,0xf1},
    {0xe0,0x1f,0xe0,0x1f,0xf1,0x0e,0xf1,0x0e},

    {0x01,0xe0,0x01,0xe0,0x01,0xf1,0x01,0xf1},
    {0xe0,0x01,0xe0,0x01,0xf1,0x01,0xf1,0x01},

    {0x1f,0xfe,0x1f,0xfe,0x0e,0xfe,0x0e,0xfe},
    {0xfe,0x1f,0xfe,0x1f,0xfe,0x0e,0xfe,0x0e},

    {0x01,0x1f,0x01,0x1f,0x01,0x0e,0x01,0x0e},
    {0x1f,0x01,0x1f,0x01,0x0e,0x01,0x0e,0x01},

    {0xe0,0xfe,0xe0,0xfe,0xf1,0xfe,0xf1,0xfe},
    {0xfe,0xe0,0xfe,0xe0,0xfe,0xf1,0xfe,0xf1}
};

krb5_boolean
k5_des_is_weak_key(unsigned char *keybits)
{
    unsigned int i;

    for (i = 0; i < sizeof(weak) / 8; i++) {
        if (memcmp(weak[i], keybits, 8) == 0)
            return TRUE;
    }
    return FALSE;
}
