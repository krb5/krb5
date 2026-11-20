/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/kadm5/srv/pwqual_princ.c */
/*
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
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

/* Password quality module to check passwords against principal components */

#include "k5-int.h"
#include <krb5/pwqual_plugin.h>
#include "server_internal.h"

/* Similar to data_eq_string(), but case-insensitive. */
static inline krb5_boolean
data_eq_string_case(const krb5_data d, const char *s)
{
    return d.length == strlen(s) && (d.length == 0 ||
                                     strncasecmp(d.data, s, d.length) == 0);
}

static krb5_error_code
princ_check(krb5_context context, krb5_pwqual_moddata data,
            const char *password, const char *policy_name,
            krb5_principal princ, const char **languages)
{
    int i;

    /* Don't check for principals with no password policy. */
    if (policy_name == NULL)
        return 0;

    /* Check against components of the principal. */
    if (data_eq_string_case(princ->realm, password))
        return KADM5_PASS_Q_DICT;
    for (i = 0; i < princ->length; i++) {
        if (data_eq_string_case(princ->data[i], password)) {
            k5_setmsg(context, KADM5_PASS_Q_DICT,
                      _("Password may not match principal name"));
            return KADM5_PASS_Q_DICT;
        }
    }

    return 0;
}

krb5_error_code
pwqual_princ_initvt(krb5_context context, int maj_ver, int min_ver,
                    krb5_plugin_vtable vtable)
{
    krb5_pwqual_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_pwqual_vtable)vtable;
    vt->name = "princ";
    vt->check = princ_check;
    return 0;
}
