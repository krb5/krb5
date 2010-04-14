/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2001, 2002, 2004, 2007, 2008 by the Massachusetts Institute of Technology.
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

#include "k5-int.h"
#include <assert.h>
#include "k5-thread.h"

#include <plugin_manager.h>
#include <plugin_prng.h>



krb5_error_code KRB5_CALLCONV
krb5_c_random_add_entropy(krb5_context context, unsigned int randsource,
                          const krb5_data *data)
{
    plhandle handle = plugin_manager_get_service("plugin_prng");

    plugin_prng_seed(handle, context, randsource, data);
    return 0;


}

krb5_error_code KRB5_CALLCONV
krb5_c_random_seed(krb5_context context, krb5_data *data)
{
    return krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OLDAPI, data);
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy(krb5_context context, int strong, int *success)
{
    plhandle handle = plugin_manager_get_service("plugin_prng");

    plugin_prng_os_seed(handle, context, strong, success);

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_make_octets(krb5_context context, krb5_data *data)
{
    plhandle handle = plugin_manager_get_service("plugin_prng");

    plugin_prng_rand(handle, context,  data);

    return 0;
}

int krb5int_prng_init(void)
{
    int ret = 0;
    plhandle handle = plugin_manager_get_service("plugin_prng");

    ret = plugin_prng_init(handle);

    return ret;
}

void
krb5int_prng_cleanup(void)
{
    plhandle handle = plugin_manager_get_service("plugin_prng");

    plugin_prng_cleanup(handle);

    return;
}


