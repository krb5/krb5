/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * Returns success with a null armor_key if FAST is available but not in use.
 * Returns failure if the client library does not support FAST.
 */
static inline krb5_error_code
fast_get_armor_key(krb5_context context, preauth_get_client_data_proc get_data,
                   struct _krb5_preauth_client_rock *rock,
                   krb5_keyblock **armor_key)
{
    krb5_error_code retval = 0;
    krb5_data *data;
    retval = get_data(context, rock, krb5plugin_preauth_client_fast_armor, &data);
    if (retval == 0) {
        *armor_key = (krb5_keyblock *) data->data;
        data->data = NULL;
        get_data(context, rock, krb5plugin_preauth_client_free_fast_armor,
                 &data);
    }
    return retval;
}

static inline krb5_error_code
fast_kdc_get_armor_key(krb5_context context,
                       preauth_get_entry_data_proc get_entry,
                       krb5_kdc_req *request,
                       struct _krb5_db_entry_new *client,
                       krb5_keyblock **armor_key)
{
    krb5_error_code retval;
    krb5_data *data;
    retval = get_entry(context, request, client,  krb5plugin_preauth_fast_armor,
                       &data);
    if (retval == 0) {
        *armor_key = (krb5_keyblock *) data->data;
        data->data = NULL;
        get_entry(context, request, client,
                  krb5plugin_preauth_free_fast_armor, &data);
    }
    return retval;
}



static inline krb5_error_code
fast_kdc_replace_reply_key(krb5_context context,
                           preauth_get_entry_data_proc get_data,
                           krb5_kdc_req *request)
{
    return 0;
}

static inline krb5_error_code
fast_set_kdc_verified(krb5_context context,
                      preauth_get_client_data_proc get_data,
                      struct _krb5_preauth_client_rock *rock)
{
    return 0;
}
