/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (c) 2004-2008 Apple Inc.  All Rights Reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Apple Inc. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Apple Inc. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

/*
 * pkinit_apple_client.c - Client side routines for PKINIT, Mac OS X version
 *
 * Created 20 May 2004 by Doug Mitchell at Apple.
 */

#if APPLE_PKINIT

#include "pkinit_client.h"
#include "pkinit_asn1.h"
#include "pkinit_apple_utils.h"
#include "pkinit_cms.h"
#include <assert.h>
#include <sys/errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Create a PA-PK-AS-REQ message.
 */
krb5_error_code krb5int_pkinit_as_req_create(
    krb5_context                context,
    krb5_timestamp              kctime,
    krb5_int32                  cusec,          /* microseconds */
    krb5_ui_4                   nonce,
    const krb5_checksum         *cksum,
    krb5_pkinit_signing_cert_t   client_cert,   /* required */
    const krb5_data             *trusted_CAs,   /* optional list of CA certs */
    krb5_ui_4                   num_trusted_CAs,
    const krb5_data             *kdc_cert,      /* optional KDC cert */
    krb5_data                   *as_req)        /* mallocd and RETURNED */
{
    krb5_data auth_pack = {0};
    krb5_error_code krtn;
    krb5_data content_info = {0};
    krb5int_algorithm_id *cms_types = NULL;
    krb5_ui_4 num_cms_types = 0;

    /* issuer/serial numbers for trusted_CAs and kdc_cert, if we have them */
    krb5_data *ca_issuer_sn = NULL;         /* issuer/serial_num for trusted_CAs */
    krb5_data kdc_issuer_sn = {0};          /* issuer/serial_num for kdc_cert */
    krb5_data *kdc_issuer_sn_p = NULL;

    /* optional platform-dependent CMS algorithm preference */
    krtn = krb5int_pkinit_get_cms_types(&cms_types, &num_cms_types);
    if(krtn) {
        return krtn;
    }

    /* encode the core authPack */
    krtn = krb5int_pkinit_auth_pack_encode(kctime, cusec, nonce, cksum,
                                           cms_types, num_cms_types,
                                           &auth_pack);
    if(krtn) {
        goto errOut;
    }

    /* package the AuthPack up in a SignedData inside a ContentInfo */
    krtn = krb5int_pkinit_create_cms_msg(&auth_pack,
                                         client_cert,
                                         NULL,           /* recip_cert */
                                         ECT_PkAuthData,
                                         0, NULL,        /* cms_types */
                                         &content_info);
    if(krtn) {
        goto errOut;
    }

    /* if we have trusted_CAs, get issuer/serials */
    if(trusted_CAs) {
        unsigned dex;
        ca_issuer_sn = (krb5_data *)malloc(num_trusted_CAs * sizeof(krb5_data));
        if(ca_issuer_sn == NULL) {
            krtn = ENOMEM;
            goto errOut;
        }
        for(dex=0; dex<num_trusted_CAs; dex++) {
            krtn = krb5int_pkinit_get_issuer_serial(&trusted_CAs[dex],
                                                    &ca_issuer_sn[dex]);
            if(krtn) {
                goto errOut;
            }
        }
    }

    /* If we have a KDC cert, get its issuer/serial */
    if(kdc_cert) {
        krtn = krb5int_pkinit_get_issuer_serial(kdc_cert, &kdc_issuer_sn);
        if(krtn) {
            goto errOut;
        }
        kdc_issuer_sn_p = &kdc_issuer_sn;
    }

    /* cook up PA-PK-AS-REQ */
    krtn = krb5int_pkinit_pa_pk_as_req_encode(&content_info,
                                              ca_issuer_sn, num_trusted_CAs,
                                              kdc_issuer_sn_p,
                                              as_req);

errOut:
    if(cms_types) {
        krb5int_pkinit_free_cms_types(cms_types, num_cms_types);
    }
    if(auth_pack.data) {
        free(auth_pack.data);
    }
    if(content_info.data) {
        free(content_info.data);
    }
    if(trusted_CAs) {
        unsigned dex;
        for(dex=0; dex<num_trusted_CAs; dex++) {
            free(ca_issuer_sn[dex].data);
        }
        free(ca_issuer_sn);
    }
    if(kdc_cert) {
        free(kdc_issuer_sn.data);
    }
    return krtn;
}

/*
 * Parse PA-PK-AS-REP message. Optionally evaluates the message's certificate chain.
 * Optionally returns various components.
 */
krb5_error_code krb5int_pkinit_as_rep_parse(
    krb5_context                context,
    const krb5_data             *as_rep,
    krb5_pkinit_signing_cert_t   client_cert,   /* required */
    krb5_keyblock               *key_block,     /* RETURNED */
    krb5_checksum               *checksum,      /* checksum of corresponding AS-REQ */
                                                /*   contents mallocd and RETURNED */
    krb5int_cert_sig_status     *cert_status,   /* RETURNED */

    /*
     * Cert fields, all optionally RETURNED.
     *
     * signer_cert is the full X.509 leaf cert from the incoming SignedData.
     * all_certs is an array of all of the certs in the incoming SignedData,
     *    in full X.509 form.
     */
    krb5_data               *signer_cert,   /* content mallocd */
    unsigned                *num_all_certs, /* sizeof *all_certs */
    krb5_data               **all_certs)    /* krb5_data's and their content mallocd */
{
    krb5_data reply_key_pack = {0, 0, NULL};
    krb5_error_code krtn;
    krb5_data enc_key_pack = {0, 0, NULL};
    krb5_data dh_signed_data = {0, 0, NULL};
    krb5int_cms_content_type content_type;
    krb5_pkinit_cert_db_t cert_db = NULL;
    krb5_boolean is_signed;
    krb5_boolean is_encrypted;

    assert((as_rep != NULL) && (checksum != NULL) &&
           (key_block != NULL) && (cert_status != NULL));

    /*
     * Decode the top-level PA-PK-AS-REP
     */
    krtn = krb5int_pkinit_pa_pk_as_rep_decode(as_rep, &dh_signed_data, &enc_key_pack);
    if(krtn) {
        pkiCssmErr("krb5int_pkinit_pa_pk_as_rep_decode", krtn);
        return krtn;
    }
    if(dh_signed_data.data) {
        /* not for this implementation... */
        pkiDebug("krb5int_pkinit_as_rep_parse: unexpected dh_signed_data\n");
        krtn = ASN1_BAD_FORMAT;
        goto err_out;
    }
    if(enc_key_pack.data == NULL) {
        /* REQUIRED for this implementation... */
        pkiDebug("krb5int_pkinit_as_rep_parse: no enc_key_pack\n");
        krtn = ASN1_BAD_FORMAT;
        goto err_out;
    }

    krtn = krb5_pkinit_get_client_cert_db(NULL, client_cert, &cert_db);
    if(krtn) {
        pkiDebug("krb5int_pkinit_as_rep_parse: error in krb5_pkinit_get_client_cert_db\n");
        goto err_out;
    }

    /*
     * enc_key_pack is an EnvelopedData(SignedData(keyPack), encrypted
     * with our cert (which krb5int_pkinit_parse_content_info() finds
     * implicitly).
     */
    krtn = krb5int_pkinit_parse_cms_msg(&enc_key_pack, cert_db, FALSE,
                                        &is_signed, &is_encrypted,
                                        &reply_key_pack, &content_type,
                                        signer_cert, cert_status, num_all_certs, all_certs);
    if(krtn) {
        pkiDebug("krb5int_pkinit_as_rep_parse: error decoding EnvelopedData\n");
        goto err_out;
    }
    if(!is_encrypted || !is_signed) {
        pkiDebug("krb5int_pkinit_as_rep_parse: not signed and encrypted!\n");
        krtn = KRB5_PARSE_MALFORMED;
        goto err_out;
    }
    if(content_type != ECT_PkReplyKeyKata) {
        pkiDebug("replyKeyPack eContentType %d!\n", (int)content_type);
        krtn = KRB5_PARSE_MALFORMED;
        goto err_out;
    }

    /*
     * Finally, decode that inner content as the ReplyKeyPack which contains
     * the actual key and nonce
     */
    krtn = krb5int_pkinit_reply_key_pack_decode(&reply_key_pack, key_block, checksum);
    if(krtn) {
        pkiDebug("krb5int_pkinit_as_rep_parse: error decoding ReplyKeyPack\n");
    }

err_out:
    /* free temp mallocd data that we didn't pass back to caller */
    if(reply_key_pack.data) {
        free(reply_key_pack.data);
    }
    if(enc_key_pack.data) {
        free(enc_key_pack.data);
    }
    if(dh_signed_data.data) {
        free(dh_signed_data.data);
    }
    if(cert_db) {
        krb5_pkinit_release_cert_db(cert_db);
    }
    return krtn;
}

#endif /* APPLE_PKINIT */
