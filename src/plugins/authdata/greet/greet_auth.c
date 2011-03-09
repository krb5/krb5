/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/authdata/greet/greet_auth.c */
/*
 * Copyright 2008 by the Massachusetts Institute of Technology.
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
 *
 * Sample authorization data plugin
 */

#include <string.h>
#include <errno.h>
#include <krb5/authdata_plugin.h>

typedef struct krb5_db_entry krb5_db_entry;

static krb5_error_code
greet_init(krb5_context ctx, void **blob)
{
    *blob = "hello";
    return 0;
}

static void
greet_fini(krb5_context ctx, void *blob)
{
}

static krb5_error_code
greet_authdata(krb5_context ctx, krb5_db_entry *client,
               krb5_data *req_pkt,
               krb5_kdc_req *request,
               krb5_enc_tkt_part * enc_tkt_reply)
{
#define GREET_SIZE (20)

    char *p;
    krb5_authdata *a;
    size_t count;
    krb5_authdata **new_ad;

    p = calloc(1, GREET_SIZE);
    a = calloc(1, sizeof(*a));

    if (p == NULL || a == NULL) {
        free(p);
        free(a);
        return ENOMEM;
    }
    strncpy(p, "hello there", GREET_SIZE-1);
    a->magic = KV5M_AUTHDATA;
    a->ad_type = -42;
    a->length = GREET_SIZE;
    a->contents = (unsigned char *)p;
    if (enc_tkt_reply->authorization_data == 0) {
        count = 0;
    } else {
        for (count = 0; enc_tkt_reply->authorization_data[count] != 0; count++)
            ;
    }
    new_ad = realloc(enc_tkt_reply->authorization_data,
                     (count+2) * sizeof(krb5_authdata *));
    if (new_ad == NULL) {
        free(p);
        free(a);
        return ENOMEM;
    }
    enc_tkt_reply->authorization_data = new_ad;
    new_ad[count] = a;
    new_ad[count+1] = NULL;
    return 0;
}

krb5plugin_authdata_ftable_v0 authdata_server_0 = {
    "greet",
    greet_init,
    greet_fini,
    greet_authdata,
};
