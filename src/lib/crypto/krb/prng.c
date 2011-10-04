/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2001, 2002, 2004, 2007, 2008, 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
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

krb5_error_code KRB5_CALLCONV
krb5_c_random_seed(krb5_context context, krb5_data *data)
{
    return krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OLDAPI, data);
}

/* Routines to get entropy from the OS. */
#if defined(_WIN32)

krb5_boolean
k5_get_os_entropy(unsigned char *buf, size_t len)
{
    krb5_boolean result;
    HCRYPTPROV provider;

    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT))
        return FALSE;
    result = CryptGenRandom(provider, len, buf);
    (void)CryptReleaseContext(provider, 0);
    return result;
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy(krb5_context context, int strong, int *success)
{
    int oursuccess = 0;
    char buf[1024];
    krb5_data data = make_data(buf, sizeof(buf));

    if (k5_get_os_entropy(buf, sizeof(buf)) &&
        krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OSRAND,
                                  &data) == 0)
        oursuccess = 1;
    if (success != NULL)
        *success = oursuccess;
    return 0;
}

#else /* not Windows */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* Open device, ensure that it is not a regular file, and read entropy.  Return
 * true on success, false on failure. */
static krb5_boolean
read_entropy_from_device(const char *device, unsigned char *buf, size_t len)
{
    struct stat sb;
    int fd;
    unsigned char *bp;
    size_t left;
    ssize_t count;
    krb5_boolean result = FALSE;

    fd = open(device, O_RDONLY);
    if (fd == -1)
        return FALSE;
    set_cloexec_fd(fd);
    if (fstat(fd, &sb) == -1 || S_ISREG(sb.st_mode))
        goto cleanup;

    for (bp = buf, left = len; left > 0;) {
        count = read(fd, bp, left);
        if (count <= 0)
            goto cleanup;
        left -= count;
        bp += count;
    }
    result = TRUE;

cleanup:
    close(fd);
    return result;
}

krb5_boolean
k5_get_os_entropy(unsigned char *buf, size_t len)
{
    return read_entropy_from_device("/dev/urandom", buf, len);
}

/* Read entropy from device and contribute it to the PRNG.  Returns true on
 * success. */
static krb5_boolean
add_entropy_from_device(krb5_context context, const char *device)
{
    krb5_data data;
    unsigned char buf[64];

    if (!read_entropy_from_device(device, buf, sizeof(buf)))
        return FALSE;
    data = make_data(buf, sizeof(buf));
    return (krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OSRAND,
                                      &data) == 0);
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy(krb5_context context, int strong, int *success)
{
    int unused;
    int *oursuccess = (success != NULL) ? success : &unused;

    *oursuccess = 0;
    /* If we are getting strong data then try that first.  We are
       guaranteed to cause a reseed of some kind if strong is true and
       we have both /dev/random and /dev/urandom.  We want the strong
       data included in the reseed so we get it first.*/
    if (strong) {
        if (add_entropy_from_device(context, "/dev/random"))
            *oursuccess = 1;
    }
    if (add_entropy_from_device(context, "/dev/urandom"))
        *oursuccess = 1;
    return 0;
}

#endif /* not Windows */
