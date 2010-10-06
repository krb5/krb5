/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/krb/prng/fortuna/fortuna.h
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

#ifndef FORTUNA_H
#define FORTUNA_H

#include "k5-int.h"
#include "prng.h"
#ifndef OPENSSL
#include "aes.h"
#endif
#include "enc_provider.h"
#include "sha2.h"
#include "enc_provider.h"

extern const struct krb5_prng_provider krb5int_prng_fortuna;

/* various entropy collect functions */
krb5_error_code
k5_entropy_from_device(krb5_context context, const char *device, unsigned char* buf, int buflen);
krb5_error_code
k5_entropy_dev_random(krb5_context context, unsigned char* buf, int buflen);
krb5_error_code
k5_entropy_dev_urandom(krb5_context context, unsigned char* buf, int buflen);
krb5_error_code
k5_entropy_pid(krb5_context context, unsigned char* buf, int buflen);
krb5_error_code
k5_entropy_uid(krb5_context context, unsigned char* buf, int buflen);

#ifdef TEST_FORTUNA
int test_entr(krb5_context context, unsigned char* buf, int buflen);
#endif

#define FORTUNA_OK                1  /* All is well */
#define FORTUNA_FAIL              0  /* generic failure */
#define FORTUNA_LOCKING          -12

#endif
