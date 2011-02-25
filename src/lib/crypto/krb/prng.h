/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/krb/prng.h - Header for PRNG modules */
/*
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

/*
 * PRNG modules must implement the following APIs from krb5.h:
 *   krb5_c_random_add_entropy
 *   krb5_c_random_make_octets
 *
 * PRNG modules should implement these functions.  They are called from the
 * crypto library init and cleanup functions, and can be used to setup and tear
 * down static state without thread safety concerns.
 */
int k5_prng_init(void);
void k5_prng_cleanup(void);

/* Used by PRNG modules to gather OS entropy.  Returns true on success. */
krb5_boolean k5_get_os_entropy(unsigned char *buf, size_t len);

#endif
