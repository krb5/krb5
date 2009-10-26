/*
 * plugins/authdata/saml_server/saml_kdc.h
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
 * Sample authorization data plugin
 */

#ifndef SAML_KDC_H_
#define SAML_KDC_H_ 1

#include "saml_krb.h"

extern "C" {

#include <kdb.h>
#include <kdb_ext.h>

krb5_error_code
saml_init(krb5_context ctx, void **blob);

void
saml_fini(krb5_context ctx, void *blob);

krb5_error_code
saml_authdata(krb5_context context,
              unsigned int flags,
              krb5_db_entry *client,
              krb5_db_entry *server,
              krb5_db_entry *tgs,
              krb5_keyblock *client_key,
              krb5_keyblock *server_key,
              krb5_keyblock *tgs_key,
              krb5_data *req_pkt,
              krb5_kdc_req *request,
              krb5_const_principal for_user_princ,
              krb5_enc_tkt_part *enc_tkt_request,
              krb5_enc_tkt_part *enc_tkt_reply);

}

krb5_error_code
saml_kdc_ldap_issue(krb5_context context,
                    krb5_db_entry *client,
                    krb5_db_entry *server,
                    saml2::AttributeStatement **attrs);

#endif /* SAML_KDC_H_ */

