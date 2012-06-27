/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/cm.c - Connection manager functions */
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

/*
 * This file include krb5int_cm_call_select, which is used by
 * lib/apputils/net-server.c and sometimes by sendto_kdc.c.
 */

#include "k5-int.h"
#include "os-proto.h"
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef _WIN32
#include <sys/timeb.h>
#endif
#include "cm.h"

int
k5_getcurtime(struct timeval *tvp)
{
#ifdef _WIN32
    struct _timeb tb;
    _ftime(&tb);
    tvp->tv_sec = tb.time;
    tvp->tv_usec = tb.millitm * 1000;
    /* Can _ftime fail?  */
    return 0;
#else
    if (gettimeofday(tvp, 0))
        return errno;
    return 0;
#endif
}

/*
 * Call select and return results.
 * Input: interesting file descriptors and absolute timeout
 * Output: select return value (-1 or num fds ready) and fd_sets
 * Return: 0 (for i/o available or timeout) or error code.
 */
krb5_error_code
krb5int_cm_call_select (const struct select_state *in,
                        struct select_state *out, int *sret)
{
    struct timeval now, *timo;
    krb5_error_code e;

    *out = *in;
    e = k5_getcurtime(&now);
    if (e)
        return e;
    if (out->end_time.tv_sec == 0)
        timo = 0;
    else {
        timo = &out->end_time;
        out->end_time.tv_sec -= now.tv_sec;
        out->end_time.tv_usec -= now.tv_usec;
        if (out->end_time.tv_usec < 0) {
            out->end_time.tv_usec += 1000000;
            out->end_time.tv_sec--;
        }
        if (out->end_time.tv_sec < 0) {
            *sret = 0;
            return 0;
        }
    }

    *sret = select(out->max, &out->rfds, &out->wfds, &out->xfds, timo);
    e = SOCKET_ERRNO;

    if (*sret < 0)
        return e;
    return 0;
}
