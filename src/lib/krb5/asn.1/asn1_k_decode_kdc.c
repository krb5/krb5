/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/asn1_k_decode_kdc.c */
/*
 * Copyright 1994, 2007, 2008, 2010 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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

#include "asn1_k_decode_macros.h"

asn1_error_code
asn1_decode_kdc_req(asn1buf *buf, krb5_kdc_req *val)
{
    setup();
    val->padata = NULL;
    { begin_structure();
        { krb5_kvno kvno;
            get_field(kvno,1,asn1_decode_kvno);
            if (kvno != KVNO) clean_return(KRB5KDC_ERR_BAD_PVNO); }
        get_field(val->msg_type,2,asn1_decode_msgtype);
        opt_field(val->padata,3,asn1_decode_sequence_of_pa_data,NULL);
        get_field(*val,4,asn1_decode_kdc_req_body);
        end_structure();
        val->magic = KV5M_KDC_REQ;
    }
    return 0;
error_out:
    krb5_free_pa_data(NULL, val->padata);
    val->padata = NULL;
    return retval;
}

asn1_error_code
asn1_decode_kdc_req_body(asn1buf *buf, krb5_kdc_req *val)
{
    setup();
    val->client = NULL;
    val->server = NULL;
    val->ktype = NULL;
    val->addresses = NULL;
    val->authorization_data.ciphertext.data = NULL;
    val->unenc_authdata = NULL;
    val->second_ticket = NULL;
    {
        krb5_principal psave;
        begin_structure();
        get_field(val->kdc_options,0,asn1_decode_kdc_options);
        if (tagnum == 1) { alloc_principal(val->client); }
        opt_field(val->client,1,asn1_decode_principal_name,NULL);
        alloc_principal(val->server);
        get_field(val->server,2,asn1_decode_realm);
        if (val->client != NULL) {
            retval = asn1_krb5_realm_copy(val->client,val->server);
            if (retval) clean_return(retval); }

        /* If opt_field server is missing, memory reference to server is
         * lost and results in memory leak
         */
        psave = val->server;
        opt_field(val->server,3,asn1_decode_principal_name,NULL);
        if (val->server == NULL) {
            if (psave->realm.data) {
                free(psave->realm.data);
                psave->realm.data = NULL;
                psave->realm.length=0;
            }
            free(psave);
        }
        opt_field(val->from,4,asn1_decode_kerberos_time,0);
        get_field(val->till,5,asn1_decode_kerberos_time);
        opt_field(val->rtime,6,asn1_decode_kerberos_time,0);
        get_field(val->nonce,7,asn1_decode_int32);
        get_lenfield(val->nktypes,val->ktype,8,asn1_decode_sequence_of_enctype);
        opt_field(val->addresses,9,asn1_decode_host_addresses,0);
        if (tagnum == 10) {
            get_field(val->authorization_data,10,asn1_decode_encrypted_data); }
        else {
            val->authorization_data.magic = KV5M_ENC_DATA;
            val->authorization_data.enctype = 0;
            val->authorization_data.kvno = 0;
            val->authorization_data.ciphertext.data = NULL;
            val->authorization_data.ciphertext.length = 0;
        }
        opt_field(val->second_ticket,11,asn1_decode_sequence_of_ticket,NULL);
        end_structure();
        val->magic = KV5M_KDC_REQ;
    }
    return 0;
error_out:
    krb5_free_principal(NULL, val->client);
    krb5_free_principal(NULL, val->server);
    free(val->ktype);
    krb5_free_addresses(NULL, val->addresses);
    krb5_free_data_contents(NULL, &val->authorization_data.ciphertext);
    krb5_free_tickets(NULL, val->second_ticket);
    val->client = NULL;
    val->server = NULL;
    val->ktype = NULL;
    val->addresses = NULL;
    val->unenc_authdata = NULL;
    val->second_ticket = NULL;
    return retval;
}

#ifndef DISABLE_PKINIT
/* PKINIT */
asn1_error_code
asn1_decode_pa_pk_as_req(asn1buf *buf, krb5_pa_pk_as_req *val)
{
    setup();
    val->signedAuthPack.data = NULL;
    val->trustedCertifiers = NULL;
    val->kdcPkId.data = NULL;
    {
        begin_structure();
        get_implicit_octet_string(val->signedAuthPack.length, val->signedAuthPack.data, 0);
        opt_field(val->trustedCertifiers, 1, asn1_decode_sequence_of_external_principal_identifier, NULL);
        opt_implicit_octet_string(val->kdcPkId.length, val->kdcPkId.data, 2);
        end_structure();
    }
    return 0;
error_out:
    free(val->signedAuthPack.data);
    free(val->trustedCertifiers);
    free(val->kdcPkId.data);
    val->signedAuthPack.data = NULL;
    val->trustedCertifiers = NULL;
    val->kdcPkId.data = NULL;
    return retval;
}

static void
free_trusted_ca(void *dummy, krb5_trusted_ca *val)
{
    if (val->choice == choice_trusted_cas_caName)
        free(val->u.caName.data);
    else if (val->choice == choice_trusted_cas_issuerAndSerial)
        free(val->u.issuerAndSerial.data);
    free(val);
}

asn1_error_code
asn1_decode_pa_pk_as_req_draft9(asn1buf *buf, krb5_pa_pk_as_req_draft9 *val)
{
    int i;
    setup();
    val->signedAuthPack.data = NULL;
    val->kdcCert.data = NULL;
    val->encryptionCert.data = NULL;
    val->trustedCertifiers = NULL;
    { begin_structure();
        get_implicit_octet_string(val->signedAuthPack.length, val->signedAuthPack.data, 0);
        opt_field(val->trustedCertifiers, 1, asn1_decode_sequence_of_trusted_ca, NULL);
        opt_lenfield(val->kdcCert.length, val->kdcCert.data, 2, asn1_decode_octetstring);
        opt_lenfield(val->encryptionCert.length, val->encryptionCert.data, 2, asn1_decode_octetstring);
        end_structure();
    }
    return 0;
error_out:
    free(val->signedAuthPack.data);
    free(val->kdcCert.data);
    free(val->encryptionCert.data);
    if (val->trustedCertifiers) {
        for (i = 0; val->trustedCertifiers[i]; i++)
            free_trusted_ca(NULL, val->trustedCertifiers[i]);
        free(val->trustedCertifiers);
    }
    val->signedAuthPack.data = NULL;
    val->kdcCert.data = NULL;
    val->encryptionCert.data = NULL;
    val->trustedCertifiers = NULL;
    return retval;
}

static void
free_algorithm_identifier(krb5_algorithm_identifier *val)
{
    free(val->algorithm.data);
    free(val->parameters.data);
    free(val);
}

asn1_error_code
asn1_decode_auth_pack(asn1buf *buf, krb5_auth_pack *val)
{
    int i;
    setup();
    val->clientPublicValue = NULL;
    val->pkAuthenticator.paChecksum.contents = NULL;
    val->supportedCMSTypes = NULL;
    val->clientDHNonce.data = NULL;
    val->supportedKDFs = NULL;
    { begin_structure();
        get_field(val->pkAuthenticator, 0, asn1_decode_pk_authenticator);
        if (tagnum == 1) {
            alloc_field(val->clientPublicValue);
            val->clientPublicValue->algorithm.algorithm.data = NULL;
            val->clientPublicValue->algorithm.parameters.data = NULL;
            val->clientPublicValue->subjectPublicKey.data = NULL;
        }
        /* can't call opt_field because it does decoder(&subbuf, &(val)); */
        if (asn1buf_remains(&subbuf, seqindef)) {
            if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)
                && (tagnum || taglen || asn1class != UNIVERSAL))
                clean_return(ASN1_BAD_ID);
            if (tagnum == 1) {
                retval = asn1_decode_subject_pk_info(&subbuf,
                                                     val->clientPublicValue);
                if (retval) clean_return(retval);
                if (!taglen && indef) { get_eoc(); }
                next_tag();
            } else val->clientPublicValue = NULL;
        }
        /* can't call opt_field because it does decoder(&subbuf, &(val)); */
        if (asn1buf_remains(&subbuf, seqindef)) {
            if (tagnum == 2) {
                retval = asn1_decode_sequence_of_algorithm_identifier(&subbuf, &val->supportedCMSTypes);
                if (retval) clean_return(retval);
                if (!taglen && indef) { get_eoc(); }
                next_tag();
            } else val->supportedCMSTypes = NULL;
        }
        opt_lenfield(val->clientDHNonce.length, val->clientDHNonce.data, 3, asn1_decode_octetstring);
        opt_field(val->supportedKDFs, 4, asn1_decode_sequence_of_kdf_alg_id, NULL);
        end_structure();
    }
    return 0;
error_out:
    if (val->clientPublicValue) {
        free(val->clientPublicValue->algorithm.algorithm.data);
        free(val->clientPublicValue->algorithm.parameters.data);
        free(val->clientPublicValue->subjectPublicKey.data);
        free(val->clientPublicValue);
    }
    free(val->pkAuthenticator.paChecksum.contents);
    if (val->supportedCMSTypes) {
        for (i = 0; val->supportedCMSTypes[i]; i++)
            free_algorithm_identifier(val->supportedCMSTypes[i]);
        free(val->supportedCMSTypes);
    }
    free(val->clientDHNonce.data);
    if (val->supportedKDFs) {
        for (i = 0; val->supportedKDFs[i]; i++)
            krb5_free_octet_data(NULL, val->supportedKDFs[i]);
        free(val->supportedKDFs);
        val->supportedKDFs = NULL;
    }
    val->clientPublicValue = NULL;
    val->pkAuthenticator.paChecksum.contents = NULL;
    val->supportedCMSTypes = NULL;
    val->clientDHNonce.data = NULL;
    return retval;
}

asn1_error_code
asn1_decode_auth_pack_draft9(asn1buf *buf, krb5_auth_pack_draft9 *val)
{
    setup();
    val->pkAuthenticator.kdcName = NULL;
    val->clientPublicValue = NULL;
    { begin_structure();
        get_field(val->pkAuthenticator, 0, asn1_decode_pk_authenticator_draft9);
        if (tagnum == 1) {
            alloc_field(val->clientPublicValue);
            val->clientPublicValue->algorithm.algorithm.data = NULL;
            val->clientPublicValue->algorithm.parameters.data = NULL;
            val->clientPublicValue->subjectPublicKey.data = NULL;
            /* can't call opt_field because it does decoder(&subbuf, &(val)); */
            if (asn1buf_remains(&subbuf, seqindef)) {
                if ((asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)
                    && (tagnum || taglen || asn1class != UNIVERSAL))
                    clean_return(ASN1_BAD_ID);
                if (tagnum == 1) {
                    retval = asn1_decode_subject_pk_info(&subbuf,
                                                         val->clientPublicValue);
                    if (retval) clean_return(retval);
                    if (!taglen && indef) { get_eoc(); }
                    next_tag();
                } else val->clientPublicValue = NULL;
            }
        }
        end_structure();
    }
    return 0;
error_out:
    free(val->pkAuthenticator.kdcName);
    if (val->clientPublicValue) {
        free(val->clientPublicValue->algorithm.algorithm.data);
        free(val->clientPublicValue->algorithm.parameters.data);
        free(val->clientPublicValue->subjectPublicKey.data);
        free(val->clientPublicValue);
    }
    val->pkAuthenticator.kdcName = NULL;
    val->clientPublicValue = NULL;
    return retval;
}

#endif /* DISABLE_PKINIT */
