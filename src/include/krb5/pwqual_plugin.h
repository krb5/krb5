/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * prototype/prototype.h
 *
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
 *
 *
 * Declarations for password quality plugin module implementors.
 */

#ifndef KRB5_PWQUAL_PLUGIN_H
#define KRB5_PWQUAL_PLUGIN_H

#include <krb5/krb5.h>
#include <krb5/plugin.h>
#include <kadm5/admin.h>
#include <kdb.h>

/* An abstract type for password quality module data. */
typedef struct krb5_pwqual_moddata_st *krb5_pwqual_moddata;

/* Password quality plugin vtable for major version 1. */
typedef struct krb5_pwqual_vtable_st {
    /* Optional: Initialize module data.  dictfile is the realm's configured
     * dictionary filename. */
    krb5_error_code (*open)(krb5_context context, const char *dict_file,
                            krb5_pwqual_moddata *data);

    /* Mandatory: Check a password for the principal princ, possibly making use
     * of the password policy given by policy.  Return an error if the password
     * check fails. */
    krb5_error_code (*check)(krb5_context context, krb5_pwqual_moddata data,
                             const char *password, kadm5_policy_ent_t policy,
                             krb5_principal princ);

    /* Optional: Release resources used by module data. */
    void (*close)(krb5_context context, krb5_pwqual_moddata data);
} *krb5_pwqual_vtable;

#endif /* KRB5_PWQUAL_PLUGIN_H */
