/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/krb/prng/prng.h
 *
 * Copyright 2010 by the Massachusetts Institute of Technology.
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


#ifndef PRNG_H
#define PRNG_H

#include "k5-int.h"

#if defined(FORTUNA)
#define ENTROPY_BUFSIZE 32  /* SHA256 digest length */
#elif defined(CRYPTO_IMPL_NSS)
/*
 * NSS gathers its own OS entropy, so it doesn't really matter how much we read
 * in krb5_c_random_os_entropy.  Use the same value as Yarrow (without using a
 * Yarrow constant), so that we don't read too much from /dev/random.
 */
#define ENTROPY_BUFSIZE 20
#else
#define ENTROPY_BUFSIZE YARROW_SLOW_THRESH/8  /* SHA1 digest length*/
#endif

/* prng.h */
struct krb5_prng_provider {
    char prng_name[8];
    krb5_error_code (*make_octets)(krb5_context, krb5_data *);
    krb5_error_code (*add_entropy)(krb5_context, unsigned int randsource, const krb5_data*);
    int (*init)(void);
    void (*cleanup)(void);
};

#endif
