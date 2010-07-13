/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugins/kdb/ldap/kdb_ext.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
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
 *
 *
 *
 */

#include "k5-int.h"
#include "kdb.h"
#include <stdio.h>
#include <errno.h>
#include "kdb_ldap.h"

static krb5_error_code
krb5_ldap_check_allowed_to_delegate(krb5_context context,
                                    unsigned int method,
                                    const krb5_data *request,
                                    krb5_data *response)
{
    const kdb_check_allowed_to_delegate_req *req;
    krb5_error_code code;
    krb5_tl_data *tlp;

    req = (const kdb_check_allowed_to_delegate_req *)request->data;

    code = KRB5KDC_ERR_POLICY;

    for (tlp = req->server->tl_data; tlp != NULL; tlp = tlp->tl_data_next) {
        krb5_principal acl;

        if (tlp->tl_data_type != KRB5_TL_CONSTRAINED_DELEGATION_ACL)
            continue;

        if (krb5_parse_name(context, (char *)tlp->tl_data_contents, &acl) != 0)
            continue;

        if (krb5_principal_compare(context, req->proxy, acl)) {
            code = 0;
            krb5_free_principal(context, acl);
            break;
        }
        krb5_free_principal(context, acl);
    }

    return code;
}

krb5_error_code
krb5_ldap_invoke(krb5_context context,
                 unsigned int method,
                 const krb5_data *req,
                 krb5_data *rep)
{
    krb5_error_code code = KRB5_PLUGIN_OP_NOTSUPP;

    switch (method) {
    case KRB5_KDB_METHOD_CHECK_ALLOWED_TO_DELEGATE:
        code = krb5_ldap_check_allowed_to_delegate(context, method, req, rep);
        break;
    default:
        break;
    }

    return code;
}
