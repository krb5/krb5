/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/krb5/certauth_plugin.h - certauth plugin header. */
/*
 * Copyright (C) 2017 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Certificate authorization plugin interface.  The PKINIT server module uses
 * this interface to check client certificate attributes after the certificate
 * signature has been verified.
 */
#ifndef KRB5_CERTAUTH_PLUGIN_H
#define KRB5_CERTAUTH_PLUGIN_H

#include <krb5/krb5.h>
#include <krb5/plugin.h>

/* Abstract module data type. */
typedef struct krb5_certauth_moddata_st *krb5_certauth_moddata;

typedef struct _krb5_db_entry_new krb5_db_entry;

/*
 * Optional: Initialize module data.
 */
typedef krb5_error_code
(*krb5_certauth_init_fn)(krb5_context context,
                         krb5_certauth_moddata *moddata_out);

/*
 * Optional: Clean up the module data.
 */
typedef void
(*krb5_certauth_fini_fn)(krb5_context context, krb5_certauth_moddata moddata);

/*
 * Mandatory:
 * Return 0 if the DER-encoded cert is authorized for PKINIT authentication by
 * princ; otherwise return one of the following error codes:
 * - KRB5KDC_ERR_CLIENT_NAME_MISMATCH - incorrect SAN value
 * - KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE - incorrect EKU
 * - KRB5KDC_ERR_CERTIFICATE_MISMATCH - other extension error
 * - KRB5_PLUGIN_NO_HANDLE - the module has no opinion about cert
 *
 * - opts is used by built-in modules to receive internal data, and must be
 *   ignored by other modules.
 * - db_entry receives the client principal database entry, and can be ignored
 *   by modules that do not link with libkdb5.
 * - *authinds_out optionally returns a null-terminated list of authentication
 *   indicator strings upon KRB5_PLUGIN_NO_HANDLE or accepted authorization.
 */
typedef krb5_error_code
(*krb5_certauth_authorize_fn)(krb5_context context,
                              krb5_certauth_moddata moddata,
                              const uint8_t *cert, size_t cert_len,
                              krb5_const_principal princ, const void *opts,
                              const krb5_db_entry *db_entry,
                              char ***authinds_out);

/*
 * Free indicators allocated by a module.  Mandatory if authorize returns
 * authentication indicators.
 */
typedef void
(*krb5_certauth_free_indicator_fn)(krb5_context context,
                                   krb5_certauth_moddata moddata,
                                   char **authinds);

typedef struct krb5_certauth_vtable_st {
    char *name;
    krb5_certauth_init_fn init;
    krb5_certauth_fini_fn fini;
    krb5_certauth_authorize_fn authorize;
    krb5_certauth_free_indicator_fn free_ind;
} *krb5_certauth_vtable;

#endif /* KRB5_CERTAUTH_PLUGIN_H */
