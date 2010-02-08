/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugins/kdb/db2/kdb_ext.c
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
#include "kdb_db2.h"

static krb5_error_code
krb5_db2_check_policy_as(krb5_context context,
                         unsigned int method,
                         const krb5_data *request,
                         krb5_data *response)
{
    const kdb_check_policy_as_req *req;
    kdb_check_policy_as_rep *rep;
    krb5_error_code code;

    req = (const kdb_check_policy_as_req *)request->data;
    rep = (kdb_check_policy_as_rep *)response->data;

    rep->status = NULL;

    code = krb5_db2_lockout_check_policy(context, req->client,
                                         req->kdc_time);
    if (code == KRB5KDC_ERR_CLIENT_REVOKED)
        rep->status = "LOCKED_OUT";

    return code;
}

static krb5_error_code
krb5_db2_audit_as(krb5_context context,
                  unsigned int method,
                  const krb5_data *request,
                  krb5_data *response)
{
    const kdb_audit_as_req *req;
    krb5_error_code code;

    req = (const kdb_audit_as_req *)request->data;

    code = krb5_db2_lockout_audit(context, req->client,
                                  req->authtime, req->error_code);

    return code;
}

krb5_error_code
krb5_db2_invoke(krb5_context context,
                unsigned int method,
                const krb5_data *req,
                krb5_data *rep)
{
    krb5_error_code code = KRB5_KDB_DBTYPE_NOSUP;

    switch (method) {
    case KRB5_KDB_METHOD_CHECK_POLICY_AS:
        code = krb5_db2_check_policy_as(context, method, req, rep);
        break;
    case KRB5_KDB_METHOD_AUDIT_AS:
        code = krb5_db2_audit_as(context, method, req, rep);
        break;
    default:
        break;
    }

    return code;
}
