/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/fuzzing/fuzz_asn.c */
/*
 * Copyright (C) 2024 by Arjun. All rights reserved.
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
 * Fuzzing harness implementation for all asn decode and encode.
 */

#include "autoconf.h"
#include <k5-spake.h>

#define kMinInputLength 2
#define kMaxInputLength 2048

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef krb5_error_code (*encoder_fn)(const void *value, krb5_data **data);
typedef krb5_error_code (*decoder_fn)(const krb5_data *data, void **value);
typedef void (*freefn_fn)(krb5_context context, void *val);

static void
free_cred_enc_part_whole(krb5_context ctx, krb5_cred_enc_part *val)
{
    krb5_free_cred_enc_part(ctx, val);
    free(val);
}

static void
ktest_empty_data(krb5_data *d)
{
    if (d->data != NULL) {
        free(d->data);
        d->data = NULL;
        d->length = 0;
    }
}

static void
ktest_empty_kkdcp_message(krb5_kkdcp_message *p)
{
    ktest_empty_data(&p->kerb_message);
    ktest_empty_data(&p->target_domain);
    p->dclocator_hint = -1;
}

static void
ktest_free_kkdcp_message(krb5_context context,
                         krb5_kkdcp_message *val)
{
    if (val)
        ktest_empty_kkdcp_message(val);
    free(val);
}

static void
fuzz_asan(void **value, krb5_data *data, encoder_fn encoderfn,
          decoder_fn decoderfn, freefn_fn freefn, krb5_context context)
{
    krb5_data *data_out = NULL;
    krb5_error_code retval;

    retval = decoderfn(data, value);
    if (retval != 0)
        return;

    retval = encoderfn(*value, &data_out);

    krb5_free_data(context, data_out);
    freefn(context, *value);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_data data_in;

    if (size < kMinInputLength || size > kMaxInputLength)
        return 0;

    data_in = make_data((void *)data, size);

    ret = krb5_init_context(&context);
    if (ret)
        return 0;

    /* Source krb5_decode_leak.c */
    {
        krb5_authenticator *authent = NULL;
        fuzz_asan((void **)&authent, &data_in,
                  (encoder_fn)encode_krb5_authenticator,
                  (decoder_fn)decode_krb5_authenticator,
                  (freefn_fn)krb5_free_authenticator, context);
    }

    {
        krb5_ticket *tkt = NULL;
        fuzz_asan((void **)&tkt, &data_in,
                  (encoder_fn)encode_krb5_ticket,
                  (decoder_fn)decode_krb5_ticket,
                  (freefn_fn)krb5_free_ticket, context);
    }

    {
        krb5_keyblock *keyblk = NULL;
        fuzz_asan((void **)&keyblk, &data_in,
                  (encoder_fn)encode_krb5_encryption_key,
                  (decoder_fn)decode_krb5_encryption_key,
                  (freefn_fn)krb5_free_keyblock, context);
    }

    {
        krb5_enc_tkt_part *enc_tkt_part = NULL;
        fuzz_asan((void **)&enc_tkt_part, &data_in,
                  (encoder_fn)encode_krb5_enc_tkt_part,
                  (decoder_fn)decode_krb5_enc_tkt_part,
                  (freefn_fn)krb5_free_enc_tkt_part, context);
    }

    {
        krb5_enc_kdc_rep_part *enc_kdc_rep_part = NULL;
        fuzz_asan((void **)&enc_kdc_rep_part, &data_in,
                  (encoder_fn)encode_krb5_enc_kdc_rep_part,
                  (decoder_fn)decode_krb5_enc_kdc_rep_part,
                  (freefn_fn)krb5_free_enc_kdc_rep_part, context);
    }

    {
        krb5_kdc_rep *as_rep = NULL;
        fuzz_asan((void **)&as_rep, &data_in,
                  (encoder_fn)encode_krb5_as_rep,
                  (decoder_fn)decode_krb5_as_rep,
                  (freefn_fn)krb5_free_kdc_rep, context);
    }

    {
        krb5_kdc_rep *tgs_rep = NULL;
        fuzz_asan((void **)&tgs_rep, &data_in,
                  (encoder_fn)encode_krb5_tgs_rep,
                  (decoder_fn)decode_krb5_tgs_rep,
                  (freefn_fn)krb5_free_kdc_rep, context);
    }

    {
        krb5_ap_req *apreq = NULL;
        fuzz_asan((void **)&apreq, &data_in,
                  (encoder_fn)encode_krb5_ap_req,
                  (decoder_fn)decode_krb5_ap_req,
                  (freefn_fn)krb5_free_ap_req, context);
    }

    {
        krb5_ap_rep *aprep = NULL;
        fuzz_asan((void **)&aprep, &data_in,
                  (encoder_fn)encode_krb5_ap_rep,
                  (decoder_fn)decode_krb5_ap_rep,
                  (freefn_fn)krb5_free_ap_rep, context);
    }

    {
        krb5_ap_rep_enc_part *apenc = NULL;
        fuzz_asan((void **)&apenc, &data_in,
                  (encoder_fn)encode_krb5_ap_rep_enc_part,
                  (decoder_fn)decode_krb5_ap_rep_enc_part,
                  (freefn_fn)krb5_free_ap_rep_enc_part, context);
    }

    {
        krb5_kdc_req *asreq = NULL;
        fuzz_asan((void **)&asreq, &data_in,
                  (encoder_fn)encode_krb5_as_req,
                  (decoder_fn)decode_krb5_as_req,
                  (freefn_fn)krb5_free_kdc_req, context);
    }

    {
        krb5_kdc_req *tgsreq = NULL;
        fuzz_asan((void **)&tgsreq, &data_in,
                  (encoder_fn)encode_krb5_tgs_req,
                  (decoder_fn)decode_krb5_tgs_req,
                  (freefn_fn)krb5_free_kdc_req, context);
    }

    {
        krb5_kdc_req *kdcrb = NULL;
        fuzz_asan((void **)&kdcrb, &data_in,
                  (encoder_fn)encode_krb5_kdc_req_body,
                  (decoder_fn)decode_krb5_kdc_req_body,
                  (freefn_fn)krb5_free_kdc_req, context);
    }

    {
        krb5_safe *safe = NULL;
        fuzz_asan((void **)&safe, &data_in,
                  (encoder_fn)encode_krb5_safe,
                  (decoder_fn)decode_krb5_safe,
                  (freefn_fn)krb5_free_safe, context);
    }

    {
        krb5_priv *priv = NULL;
        fuzz_asan((void **)&priv, &data_in,
                  (encoder_fn)encode_krb5_priv,
                  (decoder_fn)decode_krb5_priv,
                  (freefn_fn)krb5_free_priv, context);
    }

    {
        krb5_priv_enc_part *enc_priv_part = NULL;
        fuzz_asan((void **)&enc_priv_part, &data_in,
                  (encoder_fn)encode_krb5_enc_priv_part,
                  (decoder_fn)decode_krb5_enc_priv_part,
                  (freefn_fn)krb5_free_priv_enc_part, context);
    }

    {
        krb5_cred *cred = NULL;
        fuzz_asan((void **)&cred, &data_in,
                  (encoder_fn)encode_krb5_cred,
                  (decoder_fn)decode_krb5_cred,
                  (freefn_fn)krb5_free_cred, context);
    }

    {
        krb5_cred_enc_part *cred_enc_part = NULL;
        fuzz_asan((void **)&cred_enc_part, &data_in,
                  (encoder_fn)encode_krb5_enc_cred_part,
                  (decoder_fn)decode_krb5_enc_cred_part,
                  (freefn_fn)free_cred_enc_part_whole, context);
    }

    {
        krb5_error *error = NULL;
        fuzz_asan((void **)&error, &data_in,
                  (encoder_fn)encode_krb5_error,
                  (decoder_fn)decode_krb5_error,
                  (freefn_fn)krb5_free_error, context);
    }

    {
        krb5_authdata *authdata = NULL;
        fuzz_asan((void **)&authdata, &data_in,
                  (encoder_fn)encode_krb5_authdata,
                  (decoder_fn)decode_krb5_authdata,
                  (freefn_fn)krb5_free_authdata, context);
    }

    {
        krb5_pa_data *padata = NULL;
        fuzz_asan((void **)&padata, &data_in,
                  (encoder_fn)encode_krb5_padata_sequence,
                  (decoder_fn)decode_krb5_padata_sequence,
                  (freefn_fn)krb5_free_pa_data, context);
    }

    {
        krb5_pa_data *typed_data = NULL;
        fuzz_asan((void **)&typed_data, &data_in,
                  (encoder_fn)encode_krb5_typed_data,
                  (decoder_fn)decode_krb5_typed_data,
                  (freefn_fn)krb5_free_pa_data, context);
    }

    {
        krb5_etype_info_entry *etype_info = NULL;
        fuzz_asan((void **)&etype_info, &data_in,
                  (encoder_fn)encode_krb5_etype_info,
                  (decoder_fn)decode_krb5_etype_info,
                  (freefn_fn)krb5_free_etype_info, context);
    }

    {
        krb5_etype_info_entry *etype_info2 = NULL;
        fuzz_asan((void **)&etype_info2, &data_in,
                  (encoder_fn)encode_krb5_etype_info2,
                  (decoder_fn)decode_krb5_etype_info2,
                  (freefn_fn)krb5_free_etype_info, context);
    }

    {
        krb5_pa_enc_ts *pa_enc_ts = NULL;
        fuzz_asan((void **)&pa_enc_ts, &data_in,
                  (encoder_fn)encode_krb5_pa_enc_ts,
                  (decoder_fn)decode_krb5_pa_enc_ts,
                  (freefn_fn)krb5_free_pa_enc_ts, context);
    }

    {
        krb5_enc_data *enc_data = NULL;
        fuzz_asan((void **)&enc_data, &data_in,
                  (encoder_fn)encode_krb5_enc_data,
                  (decoder_fn)decode_krb5_enc_data,
                  (freefn_fn)krb5_free_enc_data, context);
    }

    {
        krb5_sam_challenge_2 *sam_ch2 = NULL;
        fuzz_asan((void **)&sam_ch2, &data_in,
                  (encoder_fn)encode_krb5_sam_challenge_2,
                  (decoder_fn)decode_krb5_sam_challenge_2,
                  (freefn_fn)krb5_free_sam_challenge_2, context);
    }

    {
        krb5_sam_challenge_2_body *sam_ch2_body = NULL;
        fuzz_asan((void **)&sam_ch2_body, &data_in,
                  (encoder_fn)encode_krb5_sam_challenge_2_body,
                  (decoder_fn)decode_krb5_sam_challenge_2_body,
                  (freefn_fn)krb5_free_sam_challenge_2_body, context);
    }

    {
        krb5_sam_response_2 *sam_res2 = NULL;
        fuzz_asan((void **)&sam_res2, &data_in,
                  (encoder_fn)encode_krb5_sam_response_2,
                  (decoder_fn)decode_krb5_sam_response_2,
                  (freefn_fn)krb5_free_sam_response_2, context);
    }

    {
        krb5_enc_sam_response_enc_2 *enc_sam_res_enc_2 = NULL;
        fuzz_asan((void **)&enc_sam_res_enc_2, &data_in,
                  (encoder_fn)encode_krb5_enc_sam_response_enc_2,
                  (decoder_fn)decode_krb5_enc_sam_response_enc_2,
                  (freefn_fn)krb5_free_enc_sam_response_enc_2, context);
    }

    {
        krb5_pa_for_user *pa_for_user = NULL;
        fuzz_asan((void **)&pa_for_user, &data_in,
                  (encoder_fn)encode_krb5_pa_for_user,
                  (decoder_fn)decode_krb5_pa_for_user,
                  (freefn_fn)krb5_free_pa_for_user, context);
    }

    {
        krb5_pa_s4u_x509_user *s4u = NULL;
        fuzz_asan((void **)&s4u, &data_in,
                  (encoder_fn)encode_krb5_pa_s4u_x509_user,
                  (decoder_fn)decode_krb5_pa_s4u_x509_user,
                  (freefn_fn)krb5_free_pa_s4u_x509_user, context);
    }

    {
        krb5_ad_kdcissued *ad_kdcissued = NULL;
        fuzz_asan((void **)&ad_kdcissued, &data_in,
                  (encoder_fn)encode_krb5_ad_kdcissued,
                  (decoder_fn)decode_krb5_ad_kdcissued,
                  (freefn_fn)krb5_free_ad_kdcissued, context);
    }

    {
        krb5_iakerb_header *iakerb_header = NULL;
        fuzz_asan((void **)&iakerb_header, &data_in,
                  (encoder_fn)encode_krb5_iakerb_header,
                  (decoder_fn)decode_krb5_iakerb_header,
                  (freefn_fn)krb5_free_iakerb_header, context);
    }

    {
        krb5_iakerb_finished *iakerb_finished = NULL;
        fuzz_asan((void **)&iakerb_finished, &data_in,
                  (encoder_fn)encode_krb5_iakerb_finished,
                  (decoder_fn)decode_krb5_iakerb_finished,
                  (freefn_fn)krb5_free_iakerb_finished, context);
    }

    {
        krb5_fast_response *fast_response = NULL;
        fuzz_asan((void **)&fast_response, &data_in,
                  (encoder_fn)encode_krb5_fast_response,
                  (decoder_fn)decode_krb5_fast_response,
                  (freefn_fn)krb5_free_fast_response, context);
    }

    {
        krb5_enc_data *enc = NULL;
        fuzz_asan((void **)&enc, &data_in,
                  (encoder_fn)encode_krb5_pa_fx_fast_reply,
                  (decoder_fn)decode_krb5_pa_fx_fast_reply,
                  (freefn_fn)krb5_free_enc_data, context);
    }

    /* Source krb5_encode_test.c */
    {
        krb5_otp_tokeninfo *otp_tokeninfo = NULL;
        fuzz_asan((void **)&otp_tokeninfo, &data_in,
                  (encoder_fn)encode_krb5_otp_tokeninfo,
                  (decoder_fn)decode_krb5_otp_tokeninfo,
                  (freefn_fn)k5_free_otp_tokeninfo, context);
    }

    {
        krb5_pa_otp_challenge *pa_otp_challenge = NULL;
        fuzz_asan((void **)&pa_otp_challenge, &data_in,
                  (encoder_fn)encode_krb5_pa_otp_challenge,
                  (decoder_fn)decode_krb5_pa_otp_challenge,
                  (freefn_fn)k5_free_pa_otp_challenge, context);
    }

    {
        krb5_pa_otp_req *pa_otp_req = NULL;
        fuzz_asan((void **)&pa_otp_req, &data_in,
                  (encoder_fn)encode_krb5_pa_otp_req,
                  (decoder_fn)decode_krb5_pa_otp_req,
                  (freefn_fn)k5_free_pa_otp_req, context);
    }

    {
        krb5_data *pa_otp_enc_req = NULL;
        fuzz_asan((void **)&pa_otp_enc_req, &data_in,
                  (encoder_fn)encode_krb5_pa_otp_enc_req,
                  (decoder_fn)decode_krb5_pa_otp_enc_req,
                  (freefn_fn)krb5_free_data, context);
    }

    {
        krb5_kkdcp_message *kkdcp_message = NULL;
        fuzz_asan((void **)&kkdcp_message, &data_in,
                  (encoder_fn)encode_krb5_kkdcp_message,
                  (decoder_fn)decode_krb5_kkdcp_message,
                  (freefn_fn)ktest_free_kkdcp_message, context);
    }

    {
        krb5_cammac *cammac = NULL;
        fuzz_asan((void **)&cammac, &data_in,
                  (encoder_fn)encode_krb5_cammac,
                  (decoder_fn)decode_krb5_cammac,
                  (freefn_fn)k5_free_cammac, context);
    }

    {
        krb5_secure_cookie *secure_cookie = NULL;
        fuzz_asan((void **)&secure_cookie, &data_in,
                  (encoder_fn)encode_krb5_secure_cookie,
                  (decoder_fn)decode_krb5_secure_cookie,
                  (freefn_fn)k5_free_secure_cookie, context);
    }

    {
        krb5_spake_factor *spake_factor = NULL;
        fuzz_asan((void **)&spake_factor, &data_in,
                  (encoder_fn)encode_krb5_spake_factor,
                  (decoder_fn)decode_krb5_spake_factor,
                  (freefn_fn)k5_free_spake_factor, context);
    }

    {
        krb5_pa_spake *pa_spake = NULL;
        fuzz_asan((void **)&pa_spake, &data_in,
                  (encoder_fn)encode_krb5_pa_spake,
                  (decoder_fn)decode_krb5_pa_spake,
                  (freefn_fn)k5_free_pa_spake, context);
    }

    /* Source krb5_decode_test.c */
    {
        krb5_pa_pac_req *pa_pac_req = NULL;

        if (decode_krb5_pa_pac_req(&data_in, &pa_pac_req) == 0) {
            free(pa_pac_req);
        }
    }

    krb5_free_context(context);
    return 0;
}
