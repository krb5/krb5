/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/crypto/krb/prng/fortuna/entropy.c
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

/* various methods to collect entropy */

#include "prng.h"

#include "fortuna.h"
#include "k5-int.h"

#ifndef min
#define min(a, b)       ((a) < (b) ? (a) : (b))
#endif

krb5_error_code
k5_entropy_from_device(krb5_context context, const char *device, unsigned char* buf, int buflen)
{
    struct stat sb;
    int fd;
    unsigned char *bp;
    size_t left;
    fd = open(device, O_RDONLY);
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
    return 0;
}

krb5_error_code
k5_entropy_dev_random(krb5_context context, unsigned char* buf, int buflen)
{
    memset(buf, 0, buflen);
    return k5_entropy_from_device(context,"/dev/random", buf, buflen);
}

krb5_error_code
k5_entropy_dev_urandom(krb5_context context, unsigned char* buf, int buflen)
{
    memset(buf, 0, buflen);
    return k5_entropy_from_device(context,"/dev/urandom", buf, buflen);
}

krb5_error_code
k5_entropy_pid(krb5_context context, unsigned char* buf, int buflen)
{
    pid_t pid = getpid(); 
    int pidlen = min(buflen,(int)sizeof(&pid));
    memset(buf, 0, buflen);
    memcpy(buf, &pid, pidlen);
    return 0;
}

krb5_error_code
k5_entropy_uid(krb5_context context, unsigned char* buf, int buflen)
{
    pid_t uid = getuid(); 
    int uidlen=min(buflen,(int)sizeof(&uid));
    memset(buf, 0, buflen);
    memcpy(buf, &uid, uidlen);
    return 0;
}

#ifdef TEST_FORTUNA
int
test_entr(krb5_context context, unsigned char* buf, int buflen)
{
    char buf1[26] = "Seed To Test Fortuna PRNG";
    memset(buf, 0, buflen);
    memcpy(buf, buf1, min(buflen, 26));
    return 0;
}
#endif
