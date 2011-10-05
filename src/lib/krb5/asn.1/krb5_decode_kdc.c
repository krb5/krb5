/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/krb5_decode_kdc.c */
/*
 * Copyright 1994, 2008. 2010 by the Massachusetts Institute of Technology.
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

#include "k5-int.h"
#include "krbasn1.h"
#include "krb5_decode_macros.h"

krb5_error_code
decode_krb5_as_req(const krb5_data *code, krb5_kdc_req **repptr)
{
    setup_no_length(krb5_kdc_req *);
    alloc_field(rep);
    clear_field(rep,padata);
    clear_field(rep,client);
    clear_field(rep,server);
    clear_field(rep,ktype);
    clear_field(rep,addresses);
    clear_field(rep,authorization_data.ciphertext.data);
    clear_field(rep,unenc_authdata);
    clear_field(rep,second_ticket);

    check_apptag(10);
    retval = asn1_decode_kdc_req(&buf,rep);
    if (retval) clean_return(retval);
#ifdef KRB5_MSGTYPE_STRICT
    if (rep->msg_type != KRB5_AS_REQ) clean_return(KRB5_BADMSGTYPE);
#endif

    cleanup_manual();
error_out:
    krb5_free_kdc_req(NULL, rep);
    return retval;
}

krb5_error_code
decode_krb5_tgs_req(const krb5_data *code, krb5_kdc_req **repptr)
{
    setup_no_length(krb5_kdc_req *);
    alloc_field(rep);
    clear_field(rep,padata);
    clear_field(rep,client);
    clear_field(rep,server);
    clear_field(rep,ktype);
    clear_field(rep,addresses);
    clear_field(rep,authorization_data.ciphertext.data);
    clear_field(rep,unenc_authdata);
    clear_field(rep,second_ticket);

    check_apptag(12);
    retval = asn1_decode_kdc_req(&buf,rep);
    if (retval) clean_return(retval);
#ifdef KRB5_MSGTYPE_STRICT
    if (rep->msg_type != KRB5_TGS_REQ) clean_return(KRB5_BADMSGTYPE);
#endif

    cleanup_manual();
error_out:
    krb5_free_kdc_req(NULL, rep);
    return retval;
}

krb5_error_code
decode_krb5_kdc_req_body(const krb5_data *code, krb5_kdc_req **repptr)
{
    setup_buf_only(krb5_kdc_req *);
    alloc_field(rep);

    retval = asn1_decode_kdc_req_body(&buf,rep);
    if (retval) clean_return(retval);

    cleanup(free);
}

krb5_error_code
decode_krb5_fast_req(const krb5_data *code, krb5_fast_req **repptr)
{
    setup(krb5_fast_req *);
    alloc_field(rep);
    alloc_field(rep->req_body);
    clear_field(rep, req_body->padata);
    {begin_structure();
        get_field(rep->fast_options, 0, asn1_decode_krb5_flags);
        opt_field(rep->req_body->padata, 1, asn1_decode_sequence_of_pa_data);
        get_field(*(rep->req_body), 2, asn1_decode_kdc_req_body);
        end_structure(); }
    rep->magic  = KV5M_FAST_REQ;
    cleanup_manual();
error_out:
    if (rep) {
        if (rep->req_body)
            krb5_free_kdc_req(0, rep->req_body);
        free(rep);
    }
    return retval;
}

krb5_error_code
decode_krb5_pa_fx_fast_request(const krb5_data *code, krb5_fast_armored_req **repptr)
{
    setup(krb5_fast_armored_req *);
    alloc_field(rep);
    clear_field(rep, armor);
    {
        int indef KRB5_ATTR_UNUSED;
        unsigned int taglen KRB5_ATTR_UNUSED;
        next_tag_from_buf(buf);
        if (tagnum != 0)
            clean_return(ASN1_BAD_ID);
    }
    {begin_structure();
        opt_field(rep->armor, 0, asn1_decode_fast_armor_ptr);
        get_field(rep->req_checksum, 1, asn1_decode_checksum);
        get_field(rep->enc_part, 2, asn1_decode_encrypted_data);
        end_structure();}
    rep->magic = KV5M_FAST_ARMORED_REQ;
    cleanup(free);
}

#ifndef DISABLE_PKINIT
krb5_error_code
decode_krb5_pa_pk_as_req(const krb5_data *code, krb5_pa_pk_as_req **repptr)
{
    setup_buf_only(krb5_pa_pk_as_req *);
    alloc_field(rep);

    retval = asn1_decode_pa_pk_as_req(&buf, rep);
    if (retval) clean_return(retval);

    cleanup(free);
}

krb5_error_code
decode_krb5_pa_pk_as_req_draft9(const krb5_data *code,
                                krb5_pa_pk_as_req_draft9 **repptr)
{
    setup_buf_only(krb5_pa_pk_as_req_draft9 *);
    alloc_field(rep);

    retval = asn1_decode_pa_pk_as_req_draft9(&buf, rep);
    if (retval) clean_return(retval);

    cleanup(free);
}
#endif /* DISABLE_PKINIT */
