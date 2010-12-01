/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/krb/fast.c
 *
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
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
 *
 */

#include <k5-int.h>

/*
 * It is possible to support sending a request that includes both a FAST and
 * normal version.  This would complicate the pre-authentication logic
 * significantly.  You would need to maintain two contexts, one for FAST and
 * one for normal use.  In adition, you would need to manage the security
 * issues surrounding downgrades.  However trying FAST at all requires an armor
 * key.  Generally in obtaining the armor key, the client learns enough to know
 * that FAST is supported.  If not, the client can see FAST in the
 * preauth_required error's padata and retry with FAST.  So, this
 * implementation does not support FAST+normal.
 *
 * We store the outer version of the request to use.  The caller stores the
 * inner version.  We handle the encoding of the request body (and request) and
 * provide encoded request bodies for the caller to use as these may be used
 * for checksums.  In the AS case we also evaluate whether to continue a
 * conversation as one of the important questions there is the presence of a
 * cookie.
 */
#include "fast.h"
#include "int-proto.h"

static krb5_error_code
fast_armor_ap_request(krb5_context context,
                      struct krb5int_fast_request_state *state,
                      krb5_ccache ccache, krb5_principal target_principal)
{
    krb5_error_code retval = 0;
    krb5_creds creds, *out_creds = NULL;
    krb5_auth_context authcontext = NULL;
    krb5_data encoded_authenticator;
    krb5_fast_armor *armor = NULL;
    krb5_keyblock *subkey = NULL, *armor_key = NULL;

    encoded_authenticator.data = NULL;
    memset(&creds, 0, sizeof(creds));
    creds.server = target_principal;
    retval = krb5_cc_get_principal(context, ccache, &creds.client);
    if (retval == 0)
        retval = krb5_get_credentials(context, 0, ccache,  &creds, &out_creds);
    if (retval == 0) {
        TRACE_FAST_ARMOR_CCACHE_KEY(context, &out_creds->keyblock);
        retval = krb5_mk_req_extended(context, &authcontext,
                                      AP_OPTS_USE_SUBKEY, NULL /*data*/,
                                      out_creds, &encoded_authenticator);
    }
    if (retval == 0)
        retval = krb5_auth_con_getsendsubkey(context, authcontext, &subkey);
    if (retval == 0)
        retval = krb5_c_fx_cf2_simple(context, subkey, "subkeyarmor",
                                      &out_creds->keyblock, "ticketarmor",
                                      &armor_key);
    if (retval == 0) {
        TRACE_FAST_ARMOR_KEY(context, armor_key);
        armor = calloc(1, sizeof(krb5_fast_armor));
        if (armor == NULL)
            retval = ENOMEM;
    }
    if (retval == 0) {
        armor->armor_type = KRB5_FAST_ARMOR_AP_REQUEST;
        armor->armor_value = encoded_authenticator;
        encoded_authenticator.data = NULL;
        encoded_authenticator.length = 0;
        state->armor = armor;
        armor = NULL;
        state->armor_key = armor_key;
        armor_key = NULL;
    }
    krb5_free_keyblock(context, armor_key);
    krb5_free_keyblock(context, subkey);
    if (out_creds)
        krb5_free_creds(context, out_creds);
    /* target_principal is owned by caller. */
    creds.server = NULL;
    krb5_free_cred_contents(context, &creds);
    if (encoded_authenticator.data)
        krb5_free_data_contents(context, &encoded_authenticator);
    krb5_auth_con_free(context, authcontext);
    return retval;
}

krb5_error_code
krb5int_fast_prep_req_body(krb5_context context,
                           struct krb5int_fast_request_state *state,
                           krb5_kdc_req *request,
                           krb5_data **encoded_request_body)
{
    krb5_error_code retval = 0;
    krb5_data *local_encoded_request_body = NULL;

    assert(state != NULL);
    *encoded_request_body = NULL;
    if (state->armor_key == NULL)
        return encode_krb5_kdc_req_body(request, encoded_request_body);
    state->fast_outer_request = *request;
    state->fast_outer_request.padata = NULL;
    if (retval == 0)
        retval = encode_krb5_kdc_req_body(&state->fast_outer_request,
                                          &local_encoded_request_body);
    if (retval == 0) {
        *encoded_request_body = local_encoded_request_body;
        local_encoded_request_body = NULL;
    }
    if (local_encoded_request_body != NULL)
        krb5_free_data(context, local_encoded_request_body);
    return retval;
}

krb5_error_code
krb5int_fast_as_armor(krb5_context context,
                      struct krb5int_fast_request_state *state,
                      krb5_gic_opt_ext *opte,
                      krb5_kdc_req *request)
{
    krb5_error_code retval = 0;
    krb5_ccache ccache = NULL;
    krb5_principal target_principal = NULL;
    krb5_data *target_realm;

    krb5_clear_error_message(context);
    target_realm = krb5_princ_realm(context, request->server);
    if (opte->opt_private->fast_ccache_name) {
        TRACE_FAST_ARMOR_CCACHE(context, opte->opt_private->fast_ccache_name);
        state->fast_state_flags |= KRB5INT_FAST_ARMOR_AVAIL;
        retval = krb5_cc_resolve(context, opte->opt_private->fast_ccache_name,
                                 &ccache);
        if (retval == 0) {
            retval = krb5int_tgtname(context, target_realm, target_realm,
                                  &target_principal);
        }
        if (retval == 0) {
            krb5_data config_data;
            config_data.data = NULL;
            retval = krb5_cc_get_config(context, ccache, target_principal,
                                        KRB5_CONF_FAST_AVAIL, &config_data);
            if ((retval == 0) && config_data.data) {
                TRACE_FAST_CCACHE_CONFIG(context);
                state->fast_state_flags |= KRB5INT_FAST_DO_FAST;
            }
            krb5_free_data_contents(context, &config_data);
            retval = 0;
        }
        if (opte->opt_private->fast_flags & KRB5_FAST_REQUIRED) {
            TRACE_FAST_REQUIRED(context);
            state->fast_state_flags |= KRB5INT_FAST_DO_FAST;
        }
        if (retval == 0 && (state->fast_state_flags & KRB5INT_FAST_DO_FAST)) {
            retval = fast_armor_ap_request(context, state, ccache,
                                           target_principal);
        }
        if (retval != 0) {
            const char * errmsg;
            errmsg = krb5_get_error_message(context, retval);
            if (errmsg) {
                krb5_set_error_message(context, retval,
                                       "%s constructing AP-REQ armor", errmsg);
                krb5_free_error_message(context, errmsg);
            }
        }
    }
    if (ccache)
        krb5_cc_close(context, ccache);
    if (target_principal)
        krb5_free_principal(context, target_principal);
    return retval;
}


krb5_error_code
krb5int_fast_prep_req(krb5_context context,
                      struct krb5int_fast_request_state *state,
                      krb5_kdc_req *request,
                      const krb5_data *to_be_checksummed,
                      kdc_req_encoder_proc encoder,
                      krb5_data **encoded_request)
{
    krb5_error_code retval = 0;
    krb5_pa_data *pa_array[2];
    krb5_pa_data pa[2];
    krb5_fast_req fast_req;
    krb5_fast_armored_req *armored_req = NULL;
    krb5_data *encoded_fast_req = NULL;
    krb5_data *encoded_armored_req = NULL;
    krb5_data *local_encoded_result = NULL;
    krb5_data random_data;
    char random_buf[4];

    assert(state != NULL);
    assert(state->fast_outer_request.padata == NULL);
    memset(pa_array, 0, sizeof pa_array);
    if (state->armor_key == NULL) {
        return encoder(request, encoded_request);
    }

    TRACE_FAST_ENCODE(context);
    /* Fill in a fresh random nonce for each inner request*/
    random_data.length = 4;
    random_data.data = (char *)random_buf;
    retval = krb5_c_random_make_octets(context, &random_data);
    if (retval == 0) {
        request->nonce = 0x7fffffff & load_32_n(random_buf);
        state->nonce = request->nonce;
    }
    fast_req.req_body =  request;
    if (fast_req.req_body->padata == NULL) {
        fast_req.req_body->padata = calloc(1, sizeof(krb5_pa_data *));
        if (fast_req.req_body->padata == NULL)
            retval = ENOMEM;
    }
    fast_req.fast_options = state->fast_options;
    if (retval == 0)
        retval = encode_krb5_fast_req(&fast_req, &encoded_fast_req);
    if (retval == 0) {
        armored_req = calloc(1, sizeof(krb5_fast_armored_req));
        if (armored_req == NULL)
            retval = ENOMEM;
    }
    if (retval == 0)
        armored_req->armor = state->armor;
    if (retval ==0)
        retval = krb5_c_make_checksum(context, 0, state->armor_key,
                                      KRB5_KEYUSAGE_FAST_REQ_CHKSUM,
                                      to_be_checksummed,
                                      &armored_req->req_checksum);
    if (retval == 0)
        retval = krb5_encrypt_helper(context, state->armor_key,
                                     KRB5_KEYUSAGE_FAST_ENC, encoded_fast_req,
                                     &armored_req->enc_part);
    if (retval == 0)
        retval = encode_krb5_pa_fx_fast_request(armored_req,
                                                &encoded_armored_req);
    if (retval==0) {
        pa[0].pa_type = KRB5_PADATA_FX_FAST;
        pa[0].contents = (unsigned char *) encoded_armored_req->data;
        pa[0].length = encoded_armored_req->length;
        pa_array[0] = &pa[0];
    }
    state->fast_outer_request.padata = pa_array;
    if(retval == 0)
        retval = encoder(&state->fast_outer_request, &local_encoded_result);
    if (retval == 0) {
        *encoded_request = local_encoded_result;
        local_encoded_result = NULL;
    }
    if (encoded_armored_req)
        krb5_free_data(context, encoded_armored_req);
    if (armored_req) {
        armored_req->armor = NULL; /*owned by state*/
        krb5_free_fast_armored_req(context, armored_req);
    }
    if (encoded_fast_req)
        krb5_free_data(context, encoded_fast_req);
    if (local_encoded_result)
        krb5_free_data(context, local_encoded_result);
    state->fast_outer_request.padata = NULL;
    return retval;
}

static krb5_error_code
decrypt_fast_reply(krb5_context context,
                   struct krb5int_fast_request_state *state,
                   krb5_pa_data **in_padata,
                   krb5_fast_response **response)
{
    krb5_error_code retval = 0;
    krb5_data scratch;
    krb5_enc_data *encrypted_response = NULL;
    krb5_pa_data *fx_reply = NULL;
    krb5_fast_response *local_resp = NULL;

    assert(state != NULL);
    assert(state->armor_key);
    fx_reply = krb5int_find_pa_data(context, in_padata, KRB5_PADATA_FX_FAST);
    if (fx_reply == NULL)
        retval = KRB5_ERR_FAST_REQUIRED;
    TRACE_FAST_DECODE(context);
    if (retval == 0) {
        scratch.data = (char *) fx_reply->contents;
        scratch.length = fx_reply->length;
        retval = decode_krb5_pa_fx_fast_reply(&scratch, &encrypted_response);
    }
    scratch.data = NULL;
    if (retval == 0) {
        scratch.data = malloc(encrypted_response->ciphertext.length);
        if (scratch.data == NULL)
            retval = ENOMEM;
        scratch.length = encrypted_response->ciphertext.length;
    }
    if (retval == 0)
        retval = krb5_c_decrypt(context, state->armor_key,
                                KRB5_KEYUSAGE_FAST_REP, NULL,
                                encrypted_response, &scratch);
    if (retval != 0) {
        const char * errmsg;
        errmsg = krb5_get_error_message(context, retval);
        krb5_set_error_message(context, retval,
                               "%s while decrypting FAST reply", errmsg);
        krb5_free_error_message(context, errmsg);
    }
    if (retval == 0)
        retval = decode_krb5_fast_response(&scratch, &local_resp);
    if (retval == 0) {
        if (local_resp->nonce != state->nonce) {
            retval = KRB5_KDCREP_MODIFIED;
            krb5_set_error_message(context, retval, "nonce modified in FAST "
                                   "response: KDC response modified");
        }
    }
    if (retval == 0) {
        *response = local_resp;
        local_resp = NULL;
    }
    if (scratch.data)
        free(scratch.data);
    if (encrypted_response)
        krb5_free_enc_data(context, encrypted_response);
    if (local_resp)
        krb5_free_fast_response(context, local_resp);
    return retval;
}

/*
 * FAST separates two concepts: the set of padata we're using to
 * decide what pre-auth mechanisms to use and the set of padata we're
 * making available to mechanisms in order for them to respond to an
 * error.  The plugin interface in March 2009 does not permit
 * separating these concepts for the plugins.  This function makes
 * both available for future revisions to the plugin interface.  It
 * also re-encodes the padata from the current error as a encoded
 * typed-data and puts that in the e_data field.  That will allow
 * existing plugins with the old interface to find the error data.
 * The output parameter out_padata contains the padata from the error
 * whenever padata  is available (all the time with fast).
 */
krb5_error_code
krb5int_fast_process_error(krb5_context context,
                           struct krb5int_fast_request_state *state,
                           krb5_error **err_replyptr,
                           krb5_pa_data ***out_padata,
                           krb5_boolean *retry)
{
    krb5_error_code retval = 0;
    krb5_error *err_reply = *err_replyptr;

    *out_padata = NULL;
    *retry = 0;
    if (state->armor_key) {
        krb5_pa_data *fx_error_pa;
        krb5_pa_data **result = NULL;
        krb5_data scratch, *encoded_td = NULL;
        krb5_error *fx_error = NULL;
        krb5_fast_response *fast_response = NULL;

        retval = decode_krb5_padata_sequence(&err_reply->e_data, &result);
        if (retval == 0)
            retval = decrypt_fast_reply(context, state, result,
                                        &fast_response);
        if (retval) {
            /*
             * This can happen if the KDC does not understand FAST. We don't
             * expect that, but treating it as the fatal error indicated by the
             * KDC seems reasonable.
             */
            *retry = 0;
            krb5_free_pa_data(context, result);
            return 0;
        }
        krb5_free_pa_data(context, result);
        result = NULL;
        if (retval == 0) {
            fx_error_pa = krb5int_find_pa_data(context, fast_response->padata,
                                               KRB5_PADATA_FX_ERROR);
            if (fx_error_pa == NULL) {
                krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
                                       "Expecting FX_ERROR pa-data inside "
                                       "FAST container");
                retval = KRB5KDC_ERR_PREAUTH_FAILED;
            }
        }
        if (retval == 0) {
            scratch.data = (char *) fx_error_pa->contents;
            scratch.length = fx_error_pa->length;
            retval = decode_krb5_error(&scratch, &fx_error);
        }
        /*
         * krb5_pa_data and krb5_typed_data are safe to cast between:
         * they have the same type fields in the same order.
         * (krb5_preauthtype is a krb5_int32).  If krb5_typed_data is
         * ever changed then this will need to be a copy not a cast.
         */
        if (retval == 0)
            retval = encode_krb5_typed_data((const krb5_typed_data **)
                                            fast_response->padata,
                                            &encoded_td);
        if (retval == 0) {
            fx_error->e_data = *encoded_td;
            free(encoded_td); /*contents owned by fx_error*/
            encoded_td = NULL;
            krb5_free_error(context, err_reply);
            *err_replyptr = fx_error;
            fx_error = NULL;
            *out_padata = fast_response->padata;
            fast_response->padata = NULL;
            /*
             * If there is more than the fx_error padata, then we want
             * to retry the error if a cookie is present
             */
            *retry = (*out_padata)[1] != NULL;
            if (krb5int_find_pa_data(context, *out_padata,
                                     KRB5_PADATA_FX_COOKIE) == NULL)
                *retry = 0;
        }
        if (fx_error)
            krb5_free_error(context, fx_error);
        krb5_free_fast_response(context, fast_response);
    } else { /*not FAST*/
        *retry = (err_reply->e_data.length > 0);
        if ((err_reply->error == KDC_ERR_PREAUTH_REQUIRED ||
             err_reply->error == KDC_ERR_PREAUTH_FAILED) &&
            err_reply->e_data.length) {
            krb5_pa_data **result = NULL;
            retval = decode_krb5_padata_sequence(&err_reply->e_data, &result);
            if (retval == 0) {
                *out_padata = result;
                return 0;
            }
            krb5_free_pa_data(context, result);
            krb5_set_error_message(context, retval,
                                   "Error decoding padata in error reply");
            return retval;
        }
    }
    return retval;
}


krb5_error_code
krb5int_fast_process_response(krb5_context context,
                              struct krb5int_fast_request_state *state,
                              krb5_kdc_rep *resp,
                              krb5_keyblock **strengthen_key)
{
    krb5_error_code retval = 0;
    krb5_fast_response *fast_response = NULL;
    krb5_data *encoded_ticket = NULL;
    krb5_boolean cksum_valid;

    krb5_clear_error_message(context);
    *strengthen_key = NULL;
    if (state->armor_key == 0)
        return 0;
    retval = decrypt_fast_reply(context, state, resp->padata,
                                &fast_response);
    if (retval == 0) {
        if (fast_response->finished == 0) {
            retval = KRB5_KDCREP_MODIFIED;
            krb5_set_error_message(context, retval, "FAST response missing "
                                   "finish message in KDC reply");
        }
    }
    if (retval == 0)
        retval = encode_krb5_ticket(resp->ticket, &encoded_ticket);
    if (retval == 0)
        retval = krb5_c_verify_checksum(context, state->armor_key,
                                        KRB5_KEYUSAGE_FAST_FINISHED,
                                        encoded_ticket,
                                        &fast_response->finished->ticket_checksum,
                                        &cksum_valid);
    if (retval == 0 && cksum_valid == 0) {
        retval = KRB5_KDCREP_MODIFIED;
        krb5_set_error_message(context, retval,
                               "ticket modified in KDC reply");
    }
    if (retval == 0) {
        krb5_free_principal(context, resp->client);
        resp->client = fast_response->finished->client;
        fast_response->finished->client = NULL;
        *strengthen_key = fast_response->strengthen_key;
        fast_response->strengthen_key = NULL;
        krb5_free_pa_data(context, resp->padata);
        resp->padata = fast_response->padata;
        fast_response->padata = NULL;
    }
    if (fast_response)
        krb5_free_fast_response(context, fast_response);
    if (encoded_ticket)
        krb5_free_data(context, encoded_ticket);
    return retval;
}

krb5_error_code
krb5int_fast_reply_key(krb5_context context,
                       krb5_keyblock *strengthen_key,
                       krb5_keyblock *existing_key,
                       krb5_keyblock *out_key)
{
    krb5_keyblock *key = NULL;
    krb5_error_code retval = 0;
    krb5_free_keyblock_contents(context, out_key);
    if (strengthen_key) {
        retval = krb5_c_fx_cf2_simple(context, strengthen_key,
                                      "strengthenkey", existing_key,
                                      "replykey", &key);
        if (retval == 0) {
            TRACE_FAST_REPLY_KEY(context, key);
            *out_key = *key;
            free(key);
        }
    } else {
        retval = krb5_copy_keyblock_contents(context, existing_key, out_key);
    }
    return retval;
}


krb5_error_code
krb5int_fast_make_state(krb5_context context,
                        struct krb5int_fast_request_state **state)
{
    struct krb5int_fast_request_state *local_state ;

    local_state = malloc(sizeof *local_state);
    if (local_state == NULL)
        return ENOMEM;
    memset(local_state, 0, sizeof(*local_state));
    *state = local_state;
    return 0;
}

void
krb5int_fast_free_state(krb5_context context,
                        struct krb5int_fast_request_state *state)
{
    if (state == NULL)
        return;
    /*We are responsible for none of the store in the fast_outer_req*/
    krb5_free_keyblock(context, state->armor_key);
    krb5_free_fast_armor(context, state->armor);
    free(state);
}

krb5_pa_data *
krb5int_find_pa_data(krb5_context context, krb5_pa_data *const *padata,
                     krb5_preauthtype pa_type)
{
    krb5_pa_data * const *tmppa;

    if (padata == NULL)
        return NULL;

    for (tmppa = padata; *tmppa != NULL; tmppa++) {
        if ((*tmppa)->pa_type == pa_type)
            break;
    }

    return *tmppa;
}


krb5_error_code
krb5int_fast_verify_nego(krb5_context context,
                         struct krb5int_fast_request_state *state,
                         krb5_kdc_rep *rep, krb5_data *request,
                         krb5_keyblock *decrypting_key,
                         krb5_boolean *fast_avail)
{
    krb5_error_code retval = 0;
    krb5_checksum *checksum = NULL;
    krb5_pa_data *pa;
    krb5_data scratch;
    krb5_boolean valid;

    *fast_avail = FALSE;
    if (rep->enc_part2->flags& TKT_FLG_ENC_PA_REP) {
        pa = krb5int_find_pa_data(context, rep->enc_part2->enc_padata,
                                  KRB5_ENCPADATA_REQ_ENC_PA_REP);
        if (pa == NULL)
            retval = KRB5_KDCREP_MODIFIED;
        else {
            scratch.data = (char *) pa->contents;
            scratch.length = pa->length;
        }
        if (retval == 0)
            retval = decode_krb5_checksum(&scratch, &checksum);
        if (retval == 0)
            retval = krb5_c_verify_checksum(context, decrypting_key,
                                            KRB5_KEYUSAGE_AS_REQ,
                                            request, checksum, &valid);
        if (retval == 0 &&valid == 0)
            retval = KRB5_KDCREP_MODIFIED;
        if (retval == 0) {
            pa = krb5int_find_pa_data(context, rep->enc_part2->enc_padata,
                                      KRB5_PADATA_FX_FAST);
            *fast_avail = (pa != NULL);
        }
    }
    TRACE_FAST_NEGO(context, *fast_avail);
    if (checksum)
        krb5_free_checksum(context, checksum);
    return retval;
}

krb5_boolean
krb5int_upgrade_to_fast_p(krb5_context context,
                          struct krb5int_fast_request_state *state,
                          krb5_pa_data **padata)
{
    if (state->armor_key != NULL)
        return FALSE; /* Already using FAST. */
    if (!(state->fast_state_flags & KRB5INT_FAST_ARMOR_AVAIL))
        return FALSE;
    if (krb5int_find_pa_data(context, padata, KRB5_PADATA_FX_FAST) != NULL) {
        TRACE_FAST_PADATA_UPGRADE(context);
        state->fast_state_flags |= KRB5INT_FAST_DO_FAST;
        return TRUE;
    }
    return FALSE;
}
