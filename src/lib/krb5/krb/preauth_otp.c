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
#include <ctype.h>

static krb5_preauthtype otp_client_supported_pa_types[] =
    { KRB5_PADATA_OTP_CHALLENGE, 0 };

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

/* Forces the user to choose a single tokeninfo via prompting. */
static krb5_error_code
prompt_for_tokeninfo(krb5_context context, krb5_prompter_fct prompter,
                     void *prompter_data, krb5_otp_tokeninfo **tis,
                     krb5_otp_tokeninfo **out_ti)
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
    } while (ti == NULL);

    free(banner);
    *out_ti = ti;
    return 0;
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

    if (asprintf(challenge, "%s %.*s\n",
                 _("OTP Challenge:"),
                 ti->challenge.length,
                 ti->challenge.data) < 0)
        return ENOMEM;

    return 0;
}

/* Determines if a pin is required. If it is, it will be prompted for. */
static inline krb5_error_code
collect_pin(krb5_context context, krb5_prompter_fct prompter,
            void *prompter_data, const krb5_otp_tokeninfo *ti,
            krb5_data *out_pin)
{
    krb5_error_code retval;
    char otppin[1024];
    krb5_flags collect;
    krb5_data pin;

    /* If no PIN will be collected, don't prompt. */
    collect = ti->flags & (KRB5_OTP_FLAG_COLLECT_PIN |
                           KRB5_OTP_FLAG_SEPARATE_PIN);
    if (collect == 0) {
        *out_pin = empty_data();
        return 0;
    }

    /* Collect the PIN. */
    retval = doprompt(context, prompter, prompter_data, NULL,
                      _("OTP Token PIN"), otppin, sizeof(otppin));
    if (retval != 0)
        return retval;

    /* Set the PIN. */
    pin = make_data(strdup(otppin), strlen(otppin));
    if (pin.data == NULL)
        return ENOMEM;

    *out_pin = pin;
    return 0;
}

/* Builds a request using the specified tokeninfo, value and pin. */
static krb5_error_code
make_request(krb5_context ctx, krb5_otp_tokeninfo *ti, const krb5_data *value,
             const krb5_data *pin, krb5_pa_otp_req **out_req)
{
    krb5_pa_otp_req *req = NULL;
    krb5_error_code retval = 0;

    if (ti == NULL)
        return 0;

    if (ti->format == KRB5_OTP_FORMAT_BASE64)
        return ENOTSUP;

    req = calloc(1, sizeof(krb5_pa_otp_req));
    if (req == NULL)
        return ENOMEM;

    req->flags = ti->flags & KRB5_OTP_FLAG_NEXTOTP;

    retval = krb5int_copy_data_contents(ctx, &ti->vendor, &req->vendor);
    if (retval != 0)
        goto error;

    req->format = ti->format;

    retval = krb5int_copy_data_contents(ctx, &ti->token_id, &req->token_id);
    if (retval != 0)
        goto error;

    retval = krb5int_copy_data_contents(ctx, &ti->alg_id, &req->alg_id);
    if (retval != 0)
        goto error;

    retval = krb5int_copy_data_contents(ctx, value, &req->otp_value);
    if (retval != 0)
        goto error;

    if (ti->flags & KRB5_OTP_FLAG_COLLECT_PIN) {
        if (pin == NULL || pin->data == NULL) {
            retval = EINVAL; /* No pin found! */
            goto error;
        }

        if (ti->flags & KRB5_OTP_FLAG_SEPARATE_PIN) {
            retval = krb5int_copy_data_contents(ctx, pin, &req->pin);
            if (retval != 0)
                goto error;
        } else {
            krb5_free_data_contents(ctx, &req->otp_value);
            retval = asprintf(&req->otp_value.data, "%.*s%.*s",
                              pin->length, pin->data,
                              value->length, value->data);
            if (retval < 0) {
                retval = ENOMEM;
                req->otp_value = empty_data();
                goto error;
            }
            req->otp_value.length = req->pin.length + req->otp_value.length;
        }
    }

    *out_req = req;
    return 0;

error:
    k5_free_pa_otp_req(ctx, req);
    return retval;
}

/*
 * Filters a set of tokeninfos given an otp value.  If the set is reduced to
 * a single tokeninfo, it will be set in out_ti.  Otherwise, a new shallow copy
 * will be allocated in out_filtered.
 */
static inline krb5_error_code
filter_tokeninfos(krb5_context context, const char *otpvalue,
                  krb5_otp_tokeninfo **tis,
                  krb5_otp_tokeninfo ***out_filtered,
                  krb5_otp_tokeninfo **out_ti)
{
    krb5_otp_tokeninfo **filtered;
    size_t i = 0, j = 0;

    while (tis[i] != NULL)
        i++;

    filtered = calloc(i + 1, sizeof(const krb5_otp_tokeninfo *));
    if (filtered == NULL)
        return ENOMEM;

    /* Make a list of tokeninfos that match the value. */
    for (i = 0, j = 0; tis[i] != NULL; i++) {
        if (otpvalue_matches_tokeninfo(otpvalue, tis[i]))
            filtered[j++] = tis[i];
    }

    /* It is an error if we have no matching tokeninfos. */
    if (filtered[0] == NULL) {
        free(filtered);
        krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                               _("OTP value doesn't match "
                                 "any token formats"));
        return KRB5_PREAUTH_FAILED; /* We have no supported tokeninfos. */
    }

    /* Otherwise, if we have just one tokeninfo, choose it. */
    if (filtered[1] == NULL) {
        *out_ti = filtered[0];
        *out_filtered = NULL;
        free(filtered);
        return 0;
    }

    /* Otherwise, we'll return the remaining list. */
    *out_ti = NULL;
    *out_filtered = filtered;
    return 0;
}

/* Outputs the selected tokeninfo and possibly a value and pin.
 * Prompting may occur. */
static krb5_error_code
prompt_for_token(krb5_context context, krb5_prompter_fct prompter,
                 void *prompter_data, krb5_otp_tokeninfo **tis,
                 krb5_otp_tokeninfo **out_ti, krb5_data *out_value,
                 krb5_data *out_pin)
{
    krb5_otp_tokeninfo **filtered = NULL;
    krb5_otp_tokeninfo *ti = NULL;
    krb5_error_code retval;
    int i, challengers = 0;
    char *challenge = NULL;
    char otpvalue[1024];
    krb5_data value, pin;

    memset(otpvalue, 0, sizeof(otpvalue));

    if (tis == NULL || tis[0] == NULL || out_ti == NULL)
        return EINVAL;

    /* Count how many challenges we have. */
    for (i = 0; tis[i] != NULL; i++) {
        if (tis[i]->challenge.data != NULL)
            challengers++;
    }

    /* If we have only one tokeninfo as input, choose it. */
    if (i == 1)
        ti = tis[0];

    /* Setup our challenge, if present. */
    if (challengers > 0) {
        /* If we have multiple tokeninfos still, choose now. */
        if (ti == NULL) {
            retval = prompt_for_tokeninfo(context, prompter, prompter_data,
                                          tis, &ti);
            if (retval != 0)
                return retval;
        }

        /* Create the challenge prompt. */
        retval = make_challenge(ti, &challenge);
        if (retval != 0)
            return retval;
    }

    /* Prompt for token value. */
    retval = doprompt(context, prompter, prompter_data, challenge,
                      _("Enter OTP Token Value"), otpvalue, sizeof(otpvalue));
    free(challenge);
    if (retval != 0)
        return retval;

    if (ti == NULL) {
        /* Filter out tokeninfos that don't match our token value. */
        retval = filter_tokeninfos(context, otpvalue, tis, &filtered, &ti);
        if (retval != 0)
            return retval;

        /* If we still don't have a single tokeninfo, choose now. */
        if (filtered != NULL) {
            retval = prompt_for_tokeninfo(context, prompter, prompter_data,
                                          filtered, &ti);
            free(filtered);
            if (retval != 0)
                return retval;
        }
    }

    assert(ti != NULL);

    /* Set the value. */
    value = make_data(strdup(otpvalue), strlen(otpvalue));
    if (value.data == NULL)
        return ENOMEM;

    /* Collect the PIN, if necessary. */
    retval = collect_pin(context, prompter, prompter_data, ti, &pin);
    if (retval != 0) {
        krb5_free_data_contents(context, &value);
        return retval;
    }

    *out_value = value;
    *out_pin = pin;
    *out_ti = ti;
    return 0;
}

/* Encode the OTP request into a krb5_pa_data buffer. */
static krb5_error_code
set_pa_data(const krb5_pa_otp_req *req, krb5_pa_data ***pa_data_out)
{
    krb5_pa_data **out = NULL;
    krb5_data *tmp;

    /* Allocate the preauth data array and one item. */
    out = calloc(2, sizeof(krb5_pa_data *));
    if (out == NULL)
        goto error;
    out[0] = calloc(1, sizeof(krb5_pa_data));
    out[1] = NULL;
    if (out[0] == NULL)
        goto error;

    /* Encode our request into the preauth data item. */
    memset(out[0], 0, sizeof(krb5_pa_data));
    out[0]->pa_type = KRB5_PADATA_OTP_REQUEST;
    if (encode_krb5_pa_otp_req(req, &tmp) != 0)
        goto error;
    out[0]->contents = (krb5_octet *)tmp->data;
    out[0]->length = tmp->length;

    *pa_data_out = out;
    return 0;

error:
    if (out != NULL) {
        free(out[0]);
        free(out);
    }
    return ENOMEM;
}

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

/* Returns TRUE when the given tokeninfo contains the subset of features we
 * support. */
static krb5_boolean
is_tokeninfo_supported(krb5_otp_tokeninfo *ti)
{
    krb5_flags supported_flags = KRB5_OTP_FLAG_COLLECT_PIN |
                                 KRB5_OTP_FLAG_NO_COLLECT_PIN |
                                 KRB5_OTP_FLAG_SEPARATE_PIN;

    /* Flags we don't support... */
    if (ti->flags & ~supported_flags)
        return FALSE;

    /* We don't currently support hashing. */
    if (ti->supported_hash_alg != NULL || ti->iteration_count >= 0)
        return FALSE;

    /* Remove tokeninfos with invalid vendor strings. */
    if (!is_printable_string(&ti->vendor))
        return FALSE;

    /* Remove tokeninfos with non-printable challenges. */
    if (!is_printable_string(&ti->challenge))
        return FALSE;

    /* We don't currently support base64. */
    if (ti->format == KRB5_OTP_FORMAT_BASE64)
        return FALSE;

    return TRUE;
}

/* Removes unsupported tokeninfos. Returns an error if no tokeninfos remain. */
static krb5_error_code
filter_supported_tokeninfos(krb5_context context, krb5_otp_tokeninfo **tis)
{
    size_t i, j;

    /* Filter out any tokeninfos we don't support. */
    for (i = 0, j = 0; tis[i] != NULL; i++) {
        if (!is_tokeninfo_supported(tis[i]))
            k5_free_otp_tokeninfo(context, tis[i]);
        else
            tis[j++] = tis[i];
    }

    /* Terminate the array. */
    tis[j] = NULL;

    if (tis[0] != NULL)
        return 0;

    krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                           _("No supported tokens"));
    return KRB5_PREAUTH_FAILED; /* We have no supported tokeninfos. */
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
    krb5_otp_tokeninfo *ti = NULL;
    krb5_keyblock *as_key = NULL;
    krb5_pa_otp_req *req = NULL;
    krb5_error_code retval = 0;
    krb5_data tmp, value, pin;

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

    /* Remove unsupported tokeninfos. */
    retval = filter_supported_tokeninfos(context, chl->tokeninfo);
    if (retval != 0)
        goto error;

    /* Have the user select a tokeninfo and enter a password/pin. */
    retval = prompt_for_token(context, prompter, prompter_data,
                              chl->tokeninfo, &ti, &value, &pin);
    if (retval != 0)
        goto error;

    /* Make the request. */
    retval = make_request(context, ti, &value, &pin, &req);
    if (retval != 0)
        goto error;

    /* Encrypt the challenge's nonce and set it in the request. */
    retval = encrypt_nonce(context, as_key, chl, req);
    if (retval != 0)
        goto error;

    /* Encode the request into the pa_data output. */
    retval = set_pa_data(req, pa_data_out);
error:
    krb5_free_data_contents(context, &value);
    krb5_free_data_contents(context, &pin);
    k5_free_pa_otp_challenge(context, chl);
    k5_free_pa_otp_req(context, req);
    return retval;
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
