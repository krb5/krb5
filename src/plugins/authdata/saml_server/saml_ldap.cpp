/*
 * plugins/authdata/saml_server/saml_ldap.cpp
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 * LDAP SAML backend
 */

#include <string.h>
#include <errno.h>
#include <k5-int.h>
#include <krb5/authdata_plugin.h>
#include <kdb.h>
#include <kdb_ext.h>

#include "saml_kdc.h"

extern "C" {
#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_principal.h" 
#include "princ_xdr.h"
#include "ldap_err.h"
}

krb5_error_code
saml_kdc_ldap_issue(krb5_context context,
                    unsigned int flags,
                    krb5_const_principal client_princ,
                    krb5_db_entry *client,
                    krb5_db_entry *server,
                    krb5_timestamp authtime,
                    saml2::AttributeStatement **attrs)
{
    krb5_data data;
    krb5_error_code st;
    krb5_ldap_entry *ldapent;
    LDAP *ld = NULL;
    krb5_ldap_context *ldap_context = NULL;
    krb5_ldap_server_handle *ldap_server_handle = NULL;

    ldapent = (krb5_ldap_entry *)client->e_data;
    if (client->e_length != sizeof(*ldapent) ||
        ldapent->magic != KRB5_LDAP_ENTRY_MAGIC) {
        return EINVAL;
    }

    ldap_context = (krb5_ldap_context *)context->dal_handle->db_context;
    CHECK_LDAP_HANDLE(ldap_context);
    GET_HANDLE();

    data.data = ldap_get_dn(ld, ldapent->entry);
    data.length = strlen(data.data);

cleanup:
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);

    return st;
}

