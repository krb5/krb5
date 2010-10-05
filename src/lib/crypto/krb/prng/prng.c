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

#include "prng.h"

#ifdef FORTUNA
#include "fortuna.h"
const struct krb5_prng_provider *prng = &krb5int_prng_fortuna;
#elif defined(CRYPTO_IMPL_NSS)
#include "prng_nss.h"
const struct krb5_prng_provider *prng = &krb5int_prng_nss;
#else
#include "yarrow.h"
const struct krb5_prng_provider *prng = &krb5int_prng_yarrow;
#endif

/*
 * krb5int_prng_init - Returns 0 on success
 */
int krb5int_prng_init(void)
{
    int err = 0;
    err = prng->init();
    return err;
}

/*
 * krb5_c_random_add_entropy - Returns 0 on success
 */
krb5_error_code KRB5_CALLCONV
krb5_c_random_add_entropy(krb5_context context, unsigned int randsource,
                          const krb5_data *data)
{
    krb5_error_code err = 0;
    err = prng->add_entropy(context, randsource, data);
    return err;
}

/*
 * krb5_c_random_seed - Returns 0 on success
 */
krb5_error_code KRB5_CALLCONV
krb5_c_random_seed(krb5_context context, krb5_data *data)
{
    return krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OLDAPI, data);
}

/*
 * krb5_c_random_make_octets -  Returns 0 on success
 */
krb5_error_code KRB5_CALLCONV
krb5_c_random_make_octets(krb5_context context, krb5_data *data)
{
    krb5_error_code err = 0;
    err = prng->make_octets(context, data);
    return err;
}

void
krb5int_prng_cleanup (void)
{
    prng->cleanup();
    return;
}


/*
 * Routines to get entropy from the OS.  For UNIX we try /dev/urandom
 * and /dev/random.  Currently we don't do anything for Windows.
 */
#if defined(_WIN32)

krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy(krb5_context context, int strong, int *success)
{
    if (success)
        *success = 0;
    return 0;
}

#else /*Windows*/
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/*
 * Helper function to read entropy from  a random device.  Takes the
 * name of a device, opens it, makes sure it is a device and if so,
 * reads entropy.  Returns  a boolean indicating whether entropy was
 * read.
 */

/* 
 * read_entropy_from_device - Returns 0 on success
 */
static int
read_entropy_from_device(krb5_context context, const char *device)
{
    krb5_data data;
    struct stat sb;
    int fd;
    unsigned char buf[ENTROPY_BUFSIZE], *bp;
    int left;
    fd = open (device, O_RDONLY);
    if (fd == -1)
        return 0;
    set_cloexec_fd(fd);
    if (fstat(fd, &sb) == -1 || S_ISREG(sb.st_mode)) {
        close(fd);
        return 0;
    }

    for (bp = buf, left = sizeof(buf); left > 0;) {
        ssize_t count;
        count = read(fd, bp, (unsigned) left);
        if (count <= 0) {
            close(fd);
            return 0;
        }
        left -= count;
        bp += count;
    }
    close(fd);
    data.length = sizeof (buf);
    data.data = (char *) buf;
    return (krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OSRAND,
                                      &data) == 0);
}

/* 
 * krb5_c_random_os_entropy - Returns 0 on success
 */
krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy(krb5_context context, int strong, int *success)
{
    int unused;
    int *oursuccess = success ? success : &unused;

    *oursuccess = 0;
    /* If we are getting strong data then try that first.  We are
       guaranteed to cause a reseed of some kind if strong is true and
       we have both /dev/random and /dev/urandom.  We want the strong
       data included in the reseed so we get it first.*/
    if (strong) {
        if (read_entropy_from_device(context, "/dev/random"))
            *oursuccess = 1;
    }
    if (read_entropy_from_device(context, "/dev/urandom"))
        *oursuccess = 1;
    return 0;
}

#endif /*Windows or pre-OSX Mac*/

