/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/des/des_keys.c - Key functions used by Kerberos code */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "crypto_int.h"
#include <cyassl/internal.h>

typedef unsigned char DES_key[8];

/* Table of known weak and semi-weak DES keys */
static const DES_key weak_keys[] = {
    /* Weak Keys */
    {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
    {0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
    {0xE0,0xE0,0xE0,0xE0,0xF1,0xF1,0xF1,0xF1},
    {0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E},

    /* Semi-weak Key Pairs */
    {0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
    {0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},

    {0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
    {0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},

    {0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
    {0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},

    {0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
    {0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},

    {0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
    {0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},

    {0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
    {0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1}
};

/*
 * k5_des_fixup_key_parity: Forces DES key to have odd parity, parity 
 *                          bit is the lowest order bit (ie: 
 *                          positions 8, 16, ... 64).
 * @keybits 8-byte DES key
 */
void
k5_des_fixup_key_parity(unsigned char *keybits)
{
	unsigned long int i;
    char tmp;

    for (i=0; i < DES_KEY_SIZE; i++) {
        keybits[i] &= 0xfe;
        tmp = keybits[i];
        tmp ^= (tmp >> 4);
        tmp ^= (tmp >> 2);
        tmp ^= (tmp >> 1);
        tmp = (~tmp & 0x01);
        keybits[i] |= tmp;
    }
    return;
}

/*
 * k5_des_is_weak_key: returns true iff key is a weak or 
                       semi-weak DES key.
 *
 * Requires: key has correct odd parity, meaning the inverted weak
 *           and semi-weak keys are not checked.
 * 
 * @keybits 8-byte DES key
 *
 * Returns 0 on success, 1 on error
 */
krb5_boolean
k5_des_is_weak_key(unsigned char *keybits)
{
    unsigned int i;
    for (i = 0; i < (sizeof(weak_keys)/sizeof(DES_key)); i++) {
        if(!memcmp(weak_keys[i], keybits, DES_KEY_SIZE)){
            return 1;
        }
    }
    return 0;
}
