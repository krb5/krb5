/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/t_response_set.c - Test krb5_response_set */
/*
 * Copyright 2012 Red Hat, Inc.
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
 * the name of Red Hat not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original Red Hat software.
 * Red Hat makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include <k5-int.h>

#include "int-proto.h"

static int freecount = 0;

static void
check_pred(int predicate)
{
    if (!predicate)
        abort();
}

static void
check(krb5_error_code code)
{
    if (code != 0) {
        com_err("t_response_set", code, NULL);
        abort();
    }
}

static void
onfree(void *ptr)
{
    if (freecount >= 0 && (ptr == (void *)0x1234 || ptr == (void *)0x4321))
        freecount++;
    else
        freecount = -1;
}

int
main()
{
    krb5_response_set *rset;

    check(k5_response_set_new(&rset));

    check(k5_response_set_set_item(rset, "foo", (void *)0x1234, onfree));
    check(k5_response_set_set_item(rset, "bar", (void *)0x4321, onfree));
    check_pred(k5_response_set_get_item(rset, "foo") == (void *)0x1234);
    check_pred(k5_response_set_get_item(rset, "bar") == (void *)0x4321);

    freecount = 0;
    k5_response_set_reset(rset);
    check_pred(freecount == 2);

    check_pred(k5_response_set_get_item(rset, "foo") == NULL);
    check_pred(k5_response_set_get_item(rset, "bar") == NULL);

    check(k5_response_set_set_item(rset, "foo", (void *)0x1234, onfree));
    check(k5_response_set_set_item(rset, "bar", (void *)0x4321, onfree));
    check_pred(k5_response_set_get_item(rset, "foo") == (void *)0x1234);
    check_pred(k5_response_set_get_item(rset, "bar") == (void *)0x4321);

    freecount = 0;
    k5_response_set_free(rset);
    check_pred(freecount == 2);

    return 0;
}
