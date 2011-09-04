/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/asn1_k_decode_sam.c */
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
asn1_decode_sam_flags(asn1buf *buf, krb5_flags *val)
{
    return asn1_decode_krb5_flags(buf,val);
}

#define opt_string(val,n,fn) opt_lenfield((val).length,(val).data,n,fn)
#define opt_cksum(var,tagexpect,decoder)        \
    if (tagnum == (tagexpect)) {                \
        get_field_body(var,decoder); }          \
    else var.length = 0

asn1_error_code
asn1_decode_sam_challenge(asn1buf *buf, krb5_sam_challenge *val)
{
    setup();
    val->sam_type_name.data = NULL;
    val->sam_track_id.data = NULL;
    val->sam_challenge_label.data = NULL;
    val->sam_response_prompt.data = NULL;
    val->sam_pk_for_sad.data = NULL;
    val->sam_cksum.contents = NULL;
    { begin_structure();
        get_field(val->sam_type,0,asn1_decode_int32);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        opt_string(val->sam_type_name,2,asn1_decode_charstring);
        opt_string(val->sam_track_id,3,asn1_decode_charstring);
        opt_string(val->sam_challenge_label,4,asn1_decode_charstring);
        opt_string(val->sam_challenge,5,asn1_decode_charstring);
        opt_string(val->sam_response_prompt,6,asn1_decode_charstring);
        opt_string(val->sam_pk_for_sad,7,asn1_decode_charstring);
        opt_field(val->sam_nonce,8,asn1_decode_int32,0);
        opt_cksum(val->sam_cksum,9,asn1_decode_checksum);
        end_structure();
        val->magic = KV5M_SAM_CHALLENGE;
    }
    return 0;
error_out:
    krb5_free_sam_challenge_contents(NULL, val);
    return retval;
}

asn1_error_code
asn1_decode_sam_challenge_2(asn1buf *buf, krb5_sam_challenge_2 *val)
{
    krb5_checksum **cksump;
    setup();
    val->sam_challenge_2_body.data = NULL;
    val->sam_cksum = NULL;
    { char *save, *end;
        size_t alloclen;
        begin_structure();
        if (tagnum != 0) clean_return(ASN1_MISSING_FIELD);
        if (asn1class != CONTEXT_SPECIFIC || construction != CONSTRUCTED)
            clean_return(ASN1_BAD_ID);
        save = subbuf.next;
        { sequence_of_no_tagvars(&subbuf);
            end_sequence_of_no_tagvars(&subbuf);
        }
        end = subbuf.next;
        alloclen = end - save;
        val->sam_challenge_2_body.data = malloc(alloclen);
        if (!val->sam_challenge_2_body.data)
            clean_return(ENOMEM);
        val->sam_challenge_2_body.length = alloclen;
        memcpy(val->sam_challenge_2_body.data, save, alloclen);
        next_tag();
        get_field(val->sam_cksum, 1, asn1_decode_sequence_of_checksum);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_data_contents(NULL, &val->sam_challenge_2_body);
    if (val->sam_cksum) {
        for (cksump = val->sam_cksum; *cksump; cksump++)
            krb5_free_checksum(NULL, *cksump);
        free(val->sam_cksum);
        val->sam_cksum = NULL;
    }
    return retval;
}

asn1_error_code
asn1_decode_sam_challenge_2_body(asn1buf *buf, krb5_sam_challenge_2_body *val)
{
    setup();
    val->sam_type_name.data = NULL;
    val->sam_track_id.data = NULL;
    val->sam_challenge_label.data = NULL;
    val->sam_challenge.data = NULL;
    val->sam_response_prompt.data = NULL;
    val->sam_pk_for_sad.data = NULL;
    { begin_structure();
        get_field(val->sam_type,0,asn1_decode_int32);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        opt_string(val->sam_type_name,2,asn1_decode_charstring);
        opt_string(val->sam_track_id,3,asn1_decode_charstring);
        opt_string(val->sam_challenge_label,4,asn1_decode_charstring);
        opt_string(val->sam_challenge,5,asn1_decode_charstring);
        opt_string(val->sam_response_prompt,6,asn1_decode_charstring);
        opt_string(val->sam_pk_for_sad,7,asn1_decode_charstring);
        get_field(val->sam_nonce,8,asn1_decode_int32);
        get_field(val->sam_etype, 9, asn1_decode_int32);
        end_structure();
        val->magic = KV5M_SAM_CHALLENGE;
    }
    return 0;
error_out:
    krb5_free_sam_challenge_2_body_contents(NULL, val);
    return retval;
}
asn1_error_code
asn1_decode_enc_sam_key(asn1buf *buf, krb5_sam_key *val)
{
    setup();
    val->sam_key.contents = NULL;
    { begin_structure();
        get_field(val->sam_key,0,asn1_decode_encryption_key);
        end_structure();
        val->magic = KV5M_SAM_KEY;
    }
    return 0;
error_out:
    krb5_free_keyblock_contents(NULL, &val->sam_key);
    return retval;
}

asn1_error_code
asn1_decode_enc_sam_response_enc(asn1buf *buf, krb5_enc_sam_response_enc *val)
{
    setup();
    val->sam_sad.data = NULL;
    { begin_structure();
        opt_field(val->sam_nonce,0,asn1_decode_int32,0);
        opt_field(val->sam_timestamp,1,asn1_decode_kerberos_time,0);
        opt_field(val->sam_usec,2,asn1_decode_int32,0);
        opt_string(val->sam_sad,3,asn1_decode_charstring);
        end_structure();
        val->magic = KV5M_ENC_SAM_RESPONSE_ENC;
    }
    return 0;
error_out:
    krb5_free_enc_sam_response_enc_contents(NULL, val);
    return retval;
}

asn1_error_code
asn1_decode_enc_sam_response_enc_2(asn1buf *buf, krb5_enc_sam_response_enc_2 *val)
{
    setup();
    val->sam_sad.data = NULL;
    { begin_structure();
        get_field(val->sam_nonce,0,asn1_decode_int32);
        opt_string(val->sam_sad,1,asn1_decode_charstring);
        end_structure();
        val->magic = KV5M_ENC_SAM_RESPONSE_ENC_2;
    }
    return 0;
error_out:
    krb5_free_enc_sam_response_enc_2_contents(NULL, val);
    return retval;
}

#define opt_encfield(fld,tag,fn)                \
    if (tagnum == tag) {                        \
        get_field(fld,tag,fn); }                \
    else {                                      \
        fld.magic = 0;                          \
        fld.enctype = 0;                        \
        fld.kvno = 0;                           \
        fld.ciphertext.data = NULL;             \
        fld.ciphertext.length = 0;              \
    }

asn1_error_code
asn1_decode_sam_response(asn1buf *buf, krb5_sam_response *val)
{
    setup();
    val->sam_track_id.data = NULL;
    val->sam_enc_key.ciphertext.data = NULL;
    val->sam_enc_nonce_or_ts.ciphertext.data = NULL;
    { begin_structure();
        get_field(val->sam_type,0,asn1_decode_int32);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        opt_string(val->sam_track_id,2,asn1_decode_charstring);
        opt_encfield(val->sam_enc_key,3,asn1_decode_encrypted_data);
        get_field(val->sam_enc_nonce_or_ts,4,asn1_decode_encrypted_data);
        opt_field(val->sam_nonce,5,asn1_decode_int32,0);
        opt_field(val->sam_patimestamp,6,asn1_decode_kerberos_time,0);
        end_structure();
        val->magic = KV5M_SAM_RESPONSE;
    }
    return 0;
error_out:
    krb5_free_sam_response_contents(NULL, val);
    return retval;
}

asn1_error_code
asn1_decode_sam_response_2(asn1buf *buf, krb5_sam_response_2 *val)
{
    setup();
    val->sam_track_id.data = NULL;
    val->sam_enc_nonce_or_sad.ciphertext.data = NULL;
    { begin_structure();
        get_field(val->sam_type,0,asn1_decode_int32);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        opt_string(val->sam_track_id,2,asn1_decode_charstring);
        get_field(val->sam_enc_nonce_or_sad,3,asn1_decode_encrypted_data);
        get_field(val->sam_nonce,4,asn1_decode_int32);
        end_structure();
        val->magic = KV5M_SAM_RESPONSE;
    }
    return 0;
error_out:
    krb5_free_sam_response_2_contents(NULL, val);
    return retval;
}

asn1_error_code
asn1_decode_predicted_sam_response(asn1buf *buf,
                                   krb5_predicted_sam_response *val)
{
    setup();
    val->sam_key.contents = NULL;
    val->client = NULL;
    val->msd.data = NULL;
    { begin_structure();
        get_field(val->sam_key,0,asn1_decode_encryption_key);
        get_field(val->sam_flags,1,asn1_decode_sam_flags);
        get_field(val->stime,2,asn1_decode_kerberos_time);
        get_field(val->susec,3,asn1_decode_int32);
        alloc_principal(val->client);
        get_field(val->client,4,asn1_decode_realm);
        get_field(val->client,5,asn1_decode_principal_name);
        opt_string(val->msd,6,asn1_decode_charstring); /* should be octet */
        end_structure();
        val->magic = KV5M_PREDICTED_SAM_RESPONSE;
    }
    return 0;
error_out:
    krb5_free_predicted_sam_response_contents(NULL, val);
    return retval;
}
