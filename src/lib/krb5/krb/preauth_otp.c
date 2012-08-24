/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/preauth_otp.c - OTP clpreauth module */
/*
 * Copyright 2011 NORDUnet A/S.  All rights reserved.
 * Copyright 2011 Red Hat, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "int-proto.h"

#include <krb5/preauth_plugin.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <string.h>

static krb5_preauthtype otp_client_supported_pa_types[] =
    { KRB5_PADATA_OTP_CHALLENGE, 0 };

/* Tests krb5_data to see if it is printable. */
static krb5_boolean
is_printable_string(const krb5_data *data)
{
    unsigned int i;

    if (data == NULL)
        return FALSE;

    for (i = 0; i < data->length; i++) {
        if (!isprint((unsigned char)data->data[i]))
            return FALSE;
    }

    return TRUE;
}

/* Takes the nonce from the challenge and encrypts it into the request. */
static krb5_error_code
encrypt_nonce(krb5_context ctx, krb5_keyblock *key,
              const krb5_pa_otp_challenge *chl, krb5_pa_otp_req *req)
{
    krb5_error_code retval;
    krb5_enc_data encdata;
    krb5_data *er;

    /* Encode the nonce. */
    retval = encode_krb5_pa_otp_enc_req(&chl->nonce, &er);
    if (retval != 0)
        return retval;

    /* Do the encryption. */
    retval = krb5_encrypt_helper(ctx, key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                                 er, &encdata);
    krb5_free_data(ctx, er);
    if (retval != 0)
        return retval;

    free(req->enc_data.ciphertext.data);
    req->enc_data = encdata;

    return 0;
}

/* Checks to see if the user-supplied otp value matches the length and format
 * of the supplied tokeninfo. */
static int
otpvalue_matches_tokeninfo(const char *otpvalue, krb5_otp_tokeninfo *ti)
{
    int (*table[])(int c) = { isdigit, isxdigit, isalnum };

    if (otpvalue == NULL || ti == NULL)
        return 0;

    if (ti->length >= 0 && strlen(otpvalue) != (size_t)ti->length)
        return 0;

    if (ti->format >= 0 && ti->format < 3) {
        while (*otpvalue) {
            if (!(*table[ti->format])((unsigned char)*otpvalue++))
                return 0;
        }
    }

    return 1;
}

/* Removes the indexed tokeninfo from the array. */
static void
remove_tokeninfo(krb5_context ctx, krb5_otp_tokeninfo **tis, unsigned int i)
{
    unsigned int j = 0;

    if (tis == NULL)
        return;

    for (j = 0; tis[j]; j++) {
        if (j == i)
            k5_free_otp_tokeninfo(ctx, tis[j]);
        if (j >= i)
            tis[j] = tis[j+1];
    }
}

/* Performs a prompt and saves the response in the out parameter. */
static krb5_error_code
doprompt(krb5_context context, krb5_prompter_fct prompter, void *prompter_data,
         const char *banner, const char *prompttxt, char *out, size_t len)
{
    krb5_prompt prompt;
    krb5_data prompt_reply;
    krb5_error_code retval;

    if (prompttxt == NULL || out == NULL)
        return EINVAL;

    memset(out, 0, len);

    prompt_reply = make_data(out, len);
    prompt.reply = &prompt_reply;
    prompt.prompt = (char *)prompttxt;
    prompt.hidden = 1;

    retval = (*prompter)(context, prompter_data, NULL, banner, 1, &prompt);
    if (retval != 0)
        return retval;

    return 0;
}

/* Forces the user to choose a single tokeninfo via prompting.
 * Removes all other tokeninfos from the array. */
static krb5_error_code
choose_token(krb5_context context, krb5_prompter_fct prompter,
             void *prompter_data, krb5_otp_tokeninfo **tis)
{
    char *banner = NULL, *tmp, response[1024];
    krb5_otp_tokeninfo *ti = NULL;
    krb5_error_code retval = 0;
    int i = 0, j = 0;

    for (i = 0; tis[i] != NULL; i++) {
        if (asprintf(&tmp, "%s\t%d. %s %.*s\n",
                     banner ? banner :
                         _("Please choose from the following:\n"),
                     i + 1, _("Vendor:"), tis[i]->vendor.length,
                     tis[i]->vendor.data) < 0) {
            free(banner);
            return ENOMEM;
        }

        free(banner);
        banner = tmp;
    }

    do {
        retval = doprompt(context, prompter, prompter_data,
                          banner, _("Enter #"), response, sizeof(response));
        if (retval != 0) {
            free(banner);
            return retval;
        }

        errno = 0;
        j = strtol(response, NULL, 0);
        if (errno != 0) {
            free(banner);
            return errno;
        }
        if (j < 1 || j > i)
            continue;

        ti = tis[--j];
        for (i = 0; tis[i] != NULL; i++) {
            if (tis[i] != ti)
                remove_tokeninfo(context, tis, i--);
        }
    } while (ti == NULL);

    free(banner);
    return 0;
}

/* Like asprintf() but saves output into a krb5_data structure. */
static krb5_error_code
data_printf(krb5_data *data, const char *fmt, ...)
{
    va_list ap;
    char *tmp = NULL;

    if (data == NULL)
        return EINVAL;

    va_start(ap, fmt);
    if (vasprintf(&tmp, fmt, ap) < 0) {
        va_end(ap);
        return errno;
    }
    va_end(ap);

    free(data->data);
    data->data = tmp;
    data->length = strlen(tmp);

    return 0;
}

/* Takes the otp value in the request and base64 encodes it. */
static krb5_error_code
base64_encode_request(krb5_pa_otp_req *req)
{
    return ENOTSUP;
}

static int
is_tokeninfo_supported(krb5_otp_tokeninfo *ti)
{
    krb5_flags supported_flags = KRB5_OTP_FLAG_COLLECT_PIN |
                                 KRB5_OTP_FLAG_NO_COLLECT_PIN |
                                 KRB5_OTP_FLAG_SEPARATE_PIN;

    /* Flags we don't support... */
    if (ti->flags & ~supported_flags)
        return 0;

    /* We don't currently support hashing. */
    if (ti->supported_hash_alg != NULL || ti->iteration_count >= 0)
        return 0;

    /* Remove tokeninfos with invalid vendor strings. */
    if (!is_printable_string(&ti->vendor))
        return 0;

    /* We don't currently support base64. */
    if (ti->format == KRB5_OTP_FORMAT_BASE64)
        return 0;

    return 1;
}

/* Builds a challenge string from the given tokeninfo. */
static krb5_error_code
make_challenge(const krb5_otp_tokeninfo *ti, char **challenge)
{
    if (challenge == NULL)
        return EINVAL;

    *challenge = NULL;

    if (ti == NULL || ti->challenge.data == NULL)
        return 0;

    /*
     * If the challenge isn't printable, then we have some kind of binary
     * challenge which we cannot properly handle. So error out. Ideally there
     * would be some mechanism to handle binary challenges to hardware tokens.
     */
    if (!is_printable_string(&ti->challenge))
        return KRB5_PREAUTH_FAILED;

    if (asprintf(challenge, "%s %.*s\n",
                 _("OTP Challenge:"),
                 ti->challenge.length,
                 ti->challenge.data) < 0)
        return ENOMEM;

    return 0;
}

/* Sets the otp value into the request. Similarly, collects and sets
 * the pin if necessary. */
static krb5_error_code
set_value_and_collect_pin(krb5_context context, krb5_prompter_fct prompter,
                          void *prompter_data, const krb5_otp_tokeninfo *ti,
                          const char *otpvalue, krb5_pa_otp_req *req)
{
    krb5_error_code retval;
    char otppin[1024];
    krb5_flags pin;

    pin = ti->flags & (KRB5_OTP_FLAG_COLLECT_PIN | KRB5_OTP_FLAG_SEPARATE_PIN);

    /* If no PIN will be collected, just set the otp value. */
    if (pin == 0) {
        retval = data_printf(&req->otp_value, "%s", otpvalue);
        if (retval != 0)
            return retval;

        req->pin = empty_data();
        return 0;
    }

    /* Collect the PIN. */
    retval = doprompt(context, prompter, prompter_data, NULL,
                      _("OTP Token PIN"), otppin, sizeof(otppin));
    if (retval != 0)
        return retval;

    /* Set the separate PIN and Value fields. */
    if (pin & KRB5_OTP_FLAG_SEPARATE_PIN) {
        retval = data_printf(&req->otp_value, "%s", otpvalue);
        if (retval != 0)
            return retval;

        retval = data_printf(&req->pin, "%s", otppin);
        if (retval != 0)
            return retval;

    /* Prepend PIN to the Value field. */
    } else {
        retval = data_printf(&req->otp_value, "%s%s", otppin, otpvalue);
        if (retval != 0)
            return retval;

        req->pin = empty_data();
    }

    return 0;
}

/* Builds a request object to send to the KDC, prompting the user if
 * necessary. */
static krb5_error_code
make_request(krb5_context context, krb5_prompter_fct prompter,
             void *prompter_data, krb5_otp_tokeninfo **tis,
             krb5_pa_otp_req **request)
{
    krb5_error_code retval;
    int i, challengers = 0;
    char *challenge = NULL;
    char otpvalue[1024];
    krb5_pa_otp_req *req;

    memset(otpvalue, 0, sizeof(otpvalue));

    if (request == NULL || tis == NULL || tis[0] == NULL)
        return EINVAL;

    /* Filter out any tokeninfos we don't support. */
    for (i = 0; tis[i] != NULL; i++) {
        if (!is_tokeninfo_supported(tis[i])) {
            remove_tokeninfo(context, tis, i--);
            continue;
        }

        if (tis[i]->challenge.data != NULL)
            challengers++; /* Count how many challenges we have. */
    }
    if (tis[0] == NULL) {
        krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                               _("No supported tokens"));
        return KRB5_PREAUTH_FAILED; /* We have no supported tokeninfos. */
    }

    /* Setup our challenge, if present. */
    if (challengers > 0) {
        /* If we have multiple tokeninfos still, choose now. */
        if (tis[1] != NULL) {
            retval = choose_token(context, prompter, prompter_data, tis);
            if (retval != 0)
                return retval;
        }

        /* Create the challenge prompt. */
        retval = make_challenge(tis[0], &challenge);
        if (retval != 0)
            return retval;
    }

    /* Prompt for token value. */
    retval = doprompt(context, prompter, prompter_data, challenge,
                      _("Enter OTP Token Value"), otpvalue, sizeof(otpvalue));
    free(challenge);
    if (retval != 0)
        return retval;

    /* Filter out tokeninfos that don't match our token value. */
    for (i = 0; tis[i] != NULL; i++) {
        if (!otpvalue_matches_tokeninfo(otpvalue, tis[i]))
            remove_tokeninfo(context, tis, i--);
    }

    /* If we still have multiple tokeninfos, choose now. */
    if (tis[0] != NULL && tis[1] != NULL) {
        retval = choose_token(context, prompter, prompter_data, tis);
        if (retval != 0)
            return retval;
    }
    if (tis == NULL || tis[0] == NULL) {
        krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                               _("OTP value doesn't match any token formats"));
        return KRB5_PREAUTH_FAILED; /* We have no supported tokeninfos. */
    }

    /* Create the request. */
    req = calloc(1, sizeof(krb5_pa_otp_req));
    if (req == NULL)
        return ENOMEM;

    /* Collect the PIN, if necessary. */
    retval = set_value_and_collect_pin(context, prompter, prompter_data,
                                       tis[0], otpvalue, req);
    if (retval != 0) {
        k5_free_pa_otp_req(context, req);
        return retval;
    }

    /* Do Base64 encoding, if necessary. */
    if (tis[0]->format == KRB5_OTP_FORMAT_BASE64) {
        retval = base64_encode_request(req);
        if (retval != 0) {
            k5_free_pa_otp_req(context, req);
            return retval;
        }
    }

    /* Steal values from the tokeninfo. */
    req->flags = tis[0]->flags;
    req->alg_id = tis[0]->alg_id;
    req->format = tis[0]->format;
    req->token_id = tis[0]->token_id;
    req->vendor = tis[0]->vendor;
    tis[0]->alg_id = empty_data();
    tis[0]->token_id = empty_data();
    tis[0]->vendor = empty_data();

    *request = req;
    return 0;
}

static int
otp_client_get_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_REAL;
}

static krb5_error_code
otp_client_process(krb5_context context, krb5_clpreauth_moddata moddata,
                   krb5_clpreauth_modreq modreq, krb5_get_init_creds_opt *opt,
                   krb5_clpreauth_callbacks cb, krb5_clpreauth_rock rock,
                   krb5_kdc_req *request, krb5_data *encoded_request_body,
                   krb5_data *encoded_previous_request, krb5_pa_data *pa_data,
                   krb5_prompter_fct prompter, void *prompter_data,
                   krb5_pa_data ***pa_data_out)
{
    krb5_pa_otp_challenge *chl = NULL;
    krb5_pa_data **out_data = NULL;
    krb5_keyblock *as_key = NULL;
    krb5_pa_otp_req *req = NULL;
    krb5_error_code retval = 0;
    krb5_data tmp, *tmpp;

    *pa_data_out = NULL;

    /* Get FAST armor key. */
    as_key = cb->fast_armor(context, rock);
    if (as_key == NULL)
        return ENOENT;

    /* Use FAST armor key as response key. */
    retval = cb->set_as_key(context, rock, as_key);
    if (retval != 0)
        return retval;

    /* Decode the challenge. */
    tmp = make_data(pa_data->contents, pa_data->length);
    retval = decode_krb5_pa_otp_challenge(&tmp, &chl);
    if (retval != 0)
        return retval;

    /* Fill in the request info from the TokenInfo structs .*/
    retval = make_request(context, prompter, prompter_data,
                          chl->tokeninfo, &req);
    if (retval != 0) {
        k5_free_pa_otp_challenge(context, chl);
        return retval;
    }

    /* Encrypt the challenge's nonce and set it in the request. */
    retval = encrypt_nonce(context, as_key, chl, req);
    k5_free_pa_otp_challenge(context, chl);
    if (retval != 0) {
        k5_free_pa_otp_req(context, req);
        return retval;
    }

    /* Allocate the preauth data array and one item. */
    out_data = calloc(2, sizeof(krb5_pa_data *));
    if (out_data == NULL) {
        k5_free_pa_otp_req(context, req);
        return ENOMEM;
    }
    out_data[0] = calloc(1, sizeof(krb5_pa_data));
    out_data[1] = NULL;
    if (out_data[0] == NULL) {
        free(out_data);
        k5_free_pa_otp_req(context, req);
        return ENOMEM;
    }

    /* Encode our request into the preauth data item. */
    memset(out_data[0], 0, sizeof(krb5_pa_data));
    out_data[0]->pa_type = KRB5_PADATA_OTP_REQUEST;
    retval = encode_krb5_pa_otp_req(req, &tmpp);
    k5_free_pa_otp_req(context, req);
    if (retval != 0) {
        free(out_data[0]);
        free(out_data);
        return ENOMEM;
    }
    out_data[0]->contents = (krb5_octet*)tmpp->data;
    out_data[0]->length = tmpp->length;

    *pa_data_out = out_data;
    return 0;
}

krb5_error_code
clpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                     krb5_plugin_vtable vtable)
{
    krb5_clpreauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_clpreauth_vtable)vtable;
    vt->name = "otp";
    vt->pa_type_list = otp_client_supported_pa_types;
    vt->flags = otp_client_get_flags;
    vt->process = otp_client_process;
    vt->gic_opts = NULL;

    return 0;
}
