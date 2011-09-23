/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/fast_factor.h - Convenience inline functions for FAST factors */
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

#ifndef FAST_FACTOR_H

/*
 * Returns success with a null armor_key if FAST is available but not in use.
 * Returns failure if the client library does not support FAST.
 */
static inline krb5_error_code
fast_get_armor_key(krb5_context context, krb5_clpreauth_get_data_fn get_data,
                   krb5_clpreauth_rock rock, krb5_keyblock **armor_key)
{
    krb5_error_code retval = 0;
    krb5_data *data;
    retval = get_data(context, rock, krb5_clpreauth_fast_armor, &data);
    if (retval == 0) {
        *armor_key = (krb5_keyblock *) data->data;
        data->data = NULL;
        get_data(context, rock, krb5_clpreauth_free_fast_armor, &data);
    }
    return retval;
}

static inline krb5_error_code
fast_kdc_get_armor_key(krb5_context context,
                       krb5_kdcpreauth_get_data_fn get_entry,
                       krb5_kdc_req *request,
                       struct _krb5_db_entry_new *client,
                       krb5_keyblock **armor_key)
{
    krb5_error_code retval;
    krb5_data *data;
    retval = get_entry(context, request, client, krb5_kdcpreauth_fast_armor,
                       &data);
    if (retval == 0) {
        *armor_key = (krb5_keyblock *) data->data;
        data->data = NULL;
        get_entry(context, request, client,
                  krb5_kdcpreauth_free_fast_armor, &data);
    }
    return retval;
}



static inline krb5_error_code
fast_kdc_replace_reply_key(krb5_context context,
                           krb5_kdcpreauth_get_data_fn get_data,
                           krb5_kdc_req *request)
{
    return 0;
}

static inline krb5_error_code
fast_set_kdc_verified(krb5_context context,
                      krb5_clpreauth_get_data_fn get_data,
                      krb5_clpreauth_rock rock)
{
    return 0;
}

#endif /* FAST_FACTOR_H */
