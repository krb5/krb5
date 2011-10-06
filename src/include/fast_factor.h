/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/fast_factor.h - Convenience inline functions for FAST factors */
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

#ifndef FAST_FACTOR_H

static inline krb5_error_code
fast_kdc_replace_reply_key(krb5_context context,
                           krb5_kdcpreauth_callbacks cb,
                           krb5_kdcpreauth_rock rock)
{
    return 0;
}

static inline krb5_error_code
fast_set_kdc_verified(krb5_context context,
                      krb5_clpreauth_callbacks cb,
                      krb5_clpreauth_rock rock)
{
    return 0;
}

#endif /* FAST_FACTOR_H */
