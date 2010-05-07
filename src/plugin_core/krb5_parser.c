/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugin_core/krb5_parser.c
 *
 * Copyright 1990,2000,2001,2002,2003,2004,2006,2008 Massachusetts Institute of Technology.
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
 *
 * similar to  "lib/krb5/os/realm_iter.c  but for "plugins"
 *
 */

#include "k5-int.h"
#include <prof_int.h>
#include "krb5_parser.h"


krb5_error_code KRB5_CALLCONV
krb5_plugin_iterator_create(profile_t profile,  void **iter_p)
{
    static const char *const names[] = { "plugins", 0 };

    return profile_node_iterator_create(profile, names,
                                   PROFILE_ITER_LIST_SECTION |
                                   PROFILE_ITER_SECTIONS_ONLY,
                                   iter_p);
}

krb5_error_code KRB5_CALLCONV
krb5_plugin_iterator(profile_t profile, void **iter_p, char **ret_realm)
{
    return profile_iterator(iter_p, ret_realm, 0);
}

void KRB5_CALLCONV
krb5_plugin_iterator_free(profile_t profile,  void **iter_p)
{
    profile_iterator_free(iter_p);
}

void KRB5_CALLCONV
krb5_free_plugin_string(profile_t profile, char *str)
{
    profile_release_string(str);
}

