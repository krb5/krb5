/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* util/gss-kernel-lib/t_kgss_common.c - Common functions for tests */
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

#include "k5-int.h"
#include <unistd.h>
#include <gssapi/gssapi_krb5.h>
#include "t_kgss_common.h"

/* Write len bytes of data to fd, aborting on failure. */
void
rewrite(int fd, const void *data, size_t len)
{
    ssize_t r;

    while (len > 0) {
        r = write(fd, data, len);
        if (r == -1 && errno == EINTR)
            continue;
        assert(r > 0);
        data = (char *)data +r;
        len -= r;
    }
}

/* Read len bytes into buf from fd, aborting on failure. */
void
reread(int fd, void *buf, size_t len)
{
    ssize_t r;

    while (len > 0) {
        r = read(fd, buf, len);
        if (r == -1 && errno == EINTR)
            continue;
        assert(r > 0);
        buf = (char *)buf + r;
        len -= r;
    }
}

/* Send a data packet to fd using a machine-dependent length/value encoding. */
void
send_data(int fd, const void *data, size_t len)
{
    rewrite(fd, &len, sizeof(len));
    rewrite(fd, data, len);
}

/* Read a packet from fd into an allocated buffer. */
void
read_data(int fd, void **data_out, size_t *len_out)
{
    size_t len;
    void *data;

    reread(fd, &len, sizeof(len));
    data = malloc(len);
    assert(data != NULL);
    reread(fd, data, len);
    *data_out = data;
    *len_out = len;
}

/*
 * Acknowledgements are used to make the parent and child processes operate in
 * lock-step.  That way, if the child fails, the parent isn't several steps
 * ahead before it finds out.
 */

void
send_ack(int fd)
{
    rewrite(fd, "ack", 3);
}

void
read_ack(int fd)
{
    char buf[3];

    reread(fd, buf, 3);
    assert(memcmp(buf, "ack", 3) == 0);
}
