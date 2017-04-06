/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* util/support/utf8_conv.c */
/*
 * Copyright 2008 by the Massachusetts Institute of Technology.
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
 */
/*
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Copyright (C) 1999, 2000 Novell, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND
 * TREATIES. USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT
 * TO VERSION 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS
 * AVAILABLE AT HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE"
 * IN THE TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION
 * OF THIS WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP
 * PUBLIC LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM NOVELL, COULD SUBJECT
 * THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
 */

/* This work is part of OpenLDAP Software <http://www.openldap.org/>. */

/*
 * UTF-8 Conversion Routines
 *
 * These routines convert between Wide Character and UTF-8,
 * or between MultiByte and UTF-8 encodings.
 *
 * Both single character and string versions of the functions are provided.
 * All functions return -1 if the character or string cannot be converted.
 */

#include "k5-platform.h"
#include "k5-utf8.h"
#include "k5-buf.h"
#include "supp-int.h"

static unsigned char mask[] = { 0, 0x7f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };

int
k5_utf8_to_ucs2le(const char *utf8, uint8_t **ucs2_out, size_t *nbytes_out)
{
    struct k5buf buf;
    krb5_ucs2 ch;
    size_t chlen, i;
    void *p;

    *ucs2_out = NULL;
    *nbytes_out = 0;

    k5_buf_init_dynamic(&buf);

    /* Examine next UTF-8 character. */
    while (*utf8 != '\0') {
        /* Get UTF-8 sequence length from first byte. */
        chlen = KRB5_UTF8_CHARLEN2(utf8, chlen);
        if (chlen == 0 || chlen > KRB5_MAX_UTF8_LEN)
            goto invalid;

        /* First byte minus length tag */
        ch = (krb5_ucs2)(utf8[0] & mask[chlen]);

        for (i = 1; i < chlen; i++) {
            /* Subsequent bytes must start with 10. */
            if ((utf8[i] & 0xc0) != 0x80)
                goto invalid;

            /* 6 bits of data in each subsequent byte */
            ch <<= 6;
            ch |= (krb5_ucs2)(utf8[i] & 0x3f);
        }

        p = k5_buf_get_space(&buf, 2);
        if (p == NULL)
            return ENOMEM;
        store_16_le(ch, p);

        /* Move to next UTF-8 character. */
        utf8 += chlen;
    }

    *ucs2_out = buf.data;
    *nbytes_out = buf.len;
    return 0;

invalid:
    k5_buf_free(&buf);
    return EINVAL;
}

int
k5_ucs2le_to_utf8(const uint8_t *ucs2bytes, size_t nbytes, char **utf8_out)
{
    struct k5buf buf;
    krb5_ucs2 ch;
    size_t chlen, i;
    void *p;

    *utf8_out = NULL;

    if (nbytes % 2 != 0)
        return EINVAL;

    k5_buf_init_dynamic(&buf);

    for (i = 0; i < nbytes; i += 2) {
        ch = load_16_le(&ucs2bytes[i]);
        chlen = krb5int_ucs2_to_utf8(ch, NULL);
        p = k5_buf_get_space(&buf, chlen);
        if (p == NULL)
            return ENOMEM;
        (void)krb5int_ucs2_to_utf8(ch, p);
    }

    *utf8_out = buf.data;
    return 0;
}
