/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/* Implement Encrypted Challenge fast factor from
 * draft-ietf-krb-wg-preauth-framework
 */


#include "k5-int.h"
#include "fast_factor.h"

//#include <krb5/preauth_plugin.h>


#include <plugin_manager.h>
#include <plugin_pa.h>
#include "plugin_pa_impl.h"


static int
_plugin_preauth_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_REAL;
}

static krb5_error_code
_plugin_process_preauth(krb5_context context, void *plugin_context,
                void *request_context, krb5_get_init_creds_opt *opt,
                preauth_get_client_data_proc get_data_proc,
                struct _krb5_preauth_client_rock *rock, krb5_kdc_req *request,
                krb5_data *encoded_request_body,
                krb5_data *encoded_previous_request, krb5_pa_data *padata,
                krb5_prompter_fct prompter, void *prompter_data,
                preauth_get_as_key_proc gak_fct, void *gak_data,
                krb5_data *salt, krb5_data *s2kparams, krb5_keyblock *as_key,
                krb5_pa_data ***out_padata)
{
    krb5_error_code retval = 0;
    krb5_enctype enctype = 0;
    krb5_keyblock *challenge_key = NULL, *armor_key = NULL;
    krb5_data *etype_data = NULL;
    krb5int_access kaccess;

    if (krb5int_accessor(&kaccess, KRB5INT_ACCESS_VERSION) != 0)
        return 0;
    retval = fast_get_armor_key(context, get_data_proc, rock, &armor_key);
    if (retval || armor_key == NULL)
        return 0;
    retval = get_data_proc(context, rock, krb5plugin_preauth_client_get_etype, &etype_data);
    if (retval == 0) {
        enctype = *((krb5_enctype *)etype_data->data);
        if (as_key->length == 0 ||as_key->enctype != enctype)
            retval = gak_fct(context, request->client,
                             enctype, prompter, prompter_data,
                             salt, s2kparams,
                             as_key, gak_data);
    }
    if (retval == 0 && padata->length) {
        krb5_enc_data *enc = NULL;
        krb5_data scratch;
        scratch.length = padata->length;
        scratch.data = (char *) padata->contents;
        retval = krb5_c_fx_cf2_simple(context,armor_key, "kdcchallengearmor",
                                      as_key, "challengelongterm",
                                      &challenge_key);
        if (retval == 0)
            retval =kaccess.decode_enc_data(&scratch, &enc);
        scratch.data = NULL;
        if (retval == 0) {
            scratch.data = malloc(enc->ciphertext.length);
            scratch.length = enc->ciphertext.length;
            if (scratch.data == NULL)
                retval = ENOMEM;
        }
        if (retval == 0)
            retval = krb5_c_decrypt(context, challenge_key,
                                    KRB5_KEYUSAGE_ENC_CHALLENGE_KDC, NULL,
                                    enc, &scratch);
        /*
         * Per draft 11 of the preauth framework, the client MAY but is not
         * required to actually check the timestamp from the KDC other than to
         * confirm it decrypts. This code does not perform that check.
         */
        if (scratch.data)
            krb5_free_data_contents(context, &scratch);
        if (retval == 0)
            fast_set_kdc_verified(context, get_data_proc, rock);
        if (enc)
            kaccess.free_enc_data(context, enc);
    } else if (retval == 0) { /*No padata; we send*/
        krb5_enc_data enc;
        krb5_pa_data *pa = NULL;
        krb5_pa_data **pa_array = NULL;
        krb5_data *encoded_ts = NULL;
        krb5_pa_enc_ts ts;
        enc.ciphertext.data = NULL;
        retval = krb5_us_timeofday(context, &ts.patimestamp, &ts.pausec);
        if (retval == 0)
            retval = kaccess.encode_enc_ts(&ts, &encoded_ts);
        if (retval == 0)
            retval = krb5_c_fx_cf2_simple(context,
                                          armor_key, "clientchallengearmor",
                                          as_key, "challengelongterm",
                                          &challenge_key);
        if (retval == 0)
            retval = kaccess.encrypt_helper(context, challenge_key,
                                            KRB5_KEYUSAGE_ENC_CHALLENGE_CLIENT,
                                            encoded_ts, &enc);
        if (encoded_ts)
            krb5_free_data(context, encoded_ts);
        encoded_ts = NULL;
        if (retval == 0) {
            retval = kaccess.encode_enc_data(&enc, &encoded_ts);
            krb5_free_data_contents(context, &enc.ciphertext);
        }
        if (retval == 0) {
            pa = calloc(1, sizeof(krb5_pa_data));
            if (pa == NULL)
                retval = ENOMEM;
        }
        if (retval == 0) {
            pa_array = calloc(2, sizeof(krb5_pa_data *));
            if (pa_array == NULL)
                retval = ENOMEM;
        }
        if (retval == 0) {
            pa->length = encoded_ts->length;
            pa->contents = (unsigned char *) encoded_ts->data;
            pa->pa_type = KRB5_PADATA_ENCRYPTED_CHALLENGE;
            free(encoded_ts);
            encoded_ts = NULL;
            pa_array[0] = pa;
            pa = NULL;
            *out_padata = pa_array;
            pa_array = NULL;
        }
        if (pa)
            free(pa);
        if (encoded_ts)
            krb5_free_data(context, encoded_ts);
        if (pa_array)
            free(pa_array);
    }
    if (challenge_key)
        krb5_free_keyblock(context, challenge_key);
    if (armor_key)
        krb5_free_keyblock(context, armor_key);
    if (etype_data != NULL)
        get_data_proc(context, rock, krb5plugin_preauth_client_free_etype,
                      &etype_data);
    return retval;
}


static krb5_error_code
_plugin_kdc_include_padata(krb5_context context, krb5_kdc_req *request,
                   struct _krb5_db_entry_new *client,
                   struct _krb5_db_entry_new *server,
                   preauth_get_entry_data_proc get_entry_proc,
                   void *pa_module_context, krb5_pa_data *data)
{
    krb5_error_code retval = 0;
    krb5_keyblock *armor_key = NULL;
    retval = fast_kdc_get_armor_key(context, get_entry_proc, request, client, &armor_key);
    if (retval)
        return retval;
    if (armor_key == 0)
        return ENOENT;
    krb5_free_keyblock(context, armor_key);
    return 0;
}

static krb5_error_code
_plugin_kdc_verify_preauth(krb5_context context, struct _krb5_db_entry_new *client,
                   krb5_data *req_pkt, krb5_kdc_req *request,
                   krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *data,
                   preauth_get_entry_data_proc get_entry_proc,
                   void *pa_module_context, void **pa_request_context,
                   krb5_data **e_data, krb5_authdata ***authz_data)
{
    krb5_error_code retval = 0;
    krb5_timestamp now;
    krb5_enc_data *enc = NULL;
    krb5_data scratch, plain;
    krb5_keyblock *armor_key = NULL;
    krb5_pa_enc_ts *ts = NULL;
    krb5int_access kaccess;
    krb5_keyblock *client_keys = NULL;
    krb5_data *client_data = NULL;
    krb5_keyblock *challenge_key = NULL;
    int i = 0;

    plain.data = NULL;
    if (krb5int_accessor(&kaccess, KRB5INT_ACCESS_VERSION) != 0)
        return 0;

    retval = fast_kdc_get_armor_key(context, get_entry_proc, request, client, &armor_key);
    if (retval == 0 &&armor_key == NULL) {
        retval = ENOENT;
        krb5_set_error_message(context, ENOENT, "Encrypted Challenge used outside of FAST tunnel");
    }
    scratch.data = (char *) data->contents;
    scratch.length = data->length;
    if (retval == 0)
        retval = kaccess.decode_enc_data(&scratch, &enc);
    if (retval == 0) {
        plain.data =  malloc(enc->ciphertext.length);
        plain.length = enc->ciphertext.length;
        if (plain.data == NULL)
            retval = ENOMEM;
    }
    if (retval == 0)
        retval = get_entry_proc(context, request, client,
                                krb5plugin_preauth_keys, &client_data);
    if (retval == 0) {
        client_keys = (krb5_keyblock *) client_data->data;
        for (i = 0; client_keys[i].enctype&& (retval == 0); i++ ) {
            retval = krb5_c_fx_cf2_simple(context,
                                          armor_key, "clientchallengearmor",
                                          &client_keys[i], "challengelongterm",
                                          &challenge_key);
            if (retval == 0)
                retval  = krb5_c_decrypt(context, challenge_key,
                                         KRB5_KEYUSAGE_ENC_CHALLENGE_CLIENT,
                                         NULL, enc, &plain);
            if (challenge_key)
                krb5_free_keyblock(context, challenge_key);
            challenge_key = NULL;
            if (retval == 0)
                break;
            /*We failed to decrypt. Try next key*/
            retval = 0;
            krb5_free_keyblock_contents(context, &client_keys[i]);
        }
        if (client_keys[i].enctype == 0) {
            retval = KRB5KDC_ERR_PREAUTH_FAILED;
            krb5_set_error_message(context, retval, "Incorrect password  in encrypted challenge");
        } else { /*not run out of keys*/
            int j;
            assert (retval == 0);
            for (j = i+1; client_keys[j].enctype; j++)
                krb5_free_keyblock_contents(context, &client_keys[j]);
        }

    }
    if (retval == 0)
        retval = kaccess.decode_enc_ts(&plain, &ts);
    if (retval == 0)
        retval = krb5_timeofday(context, &now);
    if (retval == 0) {
        if (labs(now-ts->patimestamp) < context->clockskew) {
            enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
            /*
             * If this fails, we won't generate a reply to the client.  That
             * may cause the client to fail, but at this point the KDC has
             * considered this a success, so the return value is ignored.
             */
            fast_kdc_replace_reply_key(context, get_entry_proc, request);
            krb5_c_fx_cf2_simple(context, armor_key, "kdcchallengearmor",
                                 &client_keys[i], "challengelongterm",
                                 (krb5_keyblock **) pa_request_context);
        } else { /*skew*/
            retval = KRB5KRB_AP_ERR_SKEW;
        }
    }
    if (client_keys) {
        if (client_keys[i].enctype)
            krb5_free_keyblock_contents(context, &client_keys[i]);
        krb5_free_data(context, client_data);
    }
    if (armor_key)
        krb5_free_keyblock(context, armor_key);
    if (plain.data)
        free(plain.data);
    if (enc)
        kaccess.free_enc_data(context, enc);
    if (ts)
        kaccess.free_enc_ts(context, ts);
    return retval;
}

static krb5_error_code
_plugin_kdc_return_preauth(krb5_context context, krb5_pa_data *padata,
                   struct _krb5_db_entry_new *client, krb5_data *req_pkt,
                   krb5_kdc_req *request, krb5_kdc_rep *reply,
                   struct _krb5_key_data *client_keys,
                   krb5_keyblock *encrypting_key, krb5_pa_data **send_pa,
                   preauth_get_entry_data_proc get_entry_proc,
                   void *pa_module_context, void **pa_request_context)
{
    krb5_error_code retval = 0;
    krb5_keyblock *challenge_key = *pa_request_context;
    krb5_pa_enc_ts ts;
    krb5_data *plain = NULL;
    krb5_enc_data enc;
    krb5_data *encoded = NULL;
    krb5_pa_data *pa = NULL;
    krb5int_access kaccess;

    if (krb5int_accessor(&kaccess, KRB5INT_ACCESS_VERSION) != 0)
        return 0;
    if (challenge_key == NULL)
        return 0;
    * pa_request_context = NULL; /*this function will free the
                                  * challenge key*/
    enc.ciphertext.data = NULL; /* In case of error pass through */

    retval = krb5_us_timeofday(context, &ts.patimestamp, &ts.pausec);
    if (retval == 0)
        retval = kaccess.encode_enc_ts(&ts, &plain);
    if (retval == 0)
        retval = kaccess.encrypt_helper(context, challenge_key,
                                        KRB5_KEYUSAGE_ENC_CHALLENGE_KDC,
                                        plain, &enc);
    if (retval == 0)
        retval = kaccess.encode_enc_data(&enc, &encoded);
    if (retval == 0) {
        pa = calloc(1, sizeof(krb5_pa_data));
        if (pa == NULL)
            retval = ENOMEM;
    }
    if (retval == 0) {
        pa->pa_type = KRB5_PADATA_ENCRYPTED_CHALLENGE;
        pa->contents = (unsigned char *) encoded->data;
        pa->length = encoded->length;
        encoded->data = NULL;
        *send_pa = pa;
        pa = NULL;
    }
    if (challenge_key)
        krb5_free_keyblock(context, challenge_key);
    if (encoded)
        krb5_free_data(context, encoded);
    if (plain)
        krb5_free_data(context, plain);
    if (enc.ciphertext.data)
        krb5_free_data_contents(context, &enc.ciphertext);
    return retval;
}

static int
_plugin_kdc_preauth_flags(krb5_context context, krb5_preauthtype patype)
{
    return 0;
}

static krb5_error_code
_plugin_server_free_reqctx(krb5_context kcontext,
                                          void *pa_module_context,
                                          void **pa_request_context)
{
    return 0;
}

static krb5_error_code
_plugin_server_init(krb5_context kcontext, void **module_context, const char **realmnames)
{
    return 0;
}

static void
_plugin_server_fini(krb5_context kcontext, void *module_context)
{
    return;
}



#if 0
krb5_preauthtype supported_pa_types[] = {
    KRB5_PADATA_ENCRYPTED_CHALLENGE, 0};

struct krb5plugin_preauth_server_ftable_v1 preauthentication_server_1 = {
    "Encrypted challenge",
    &supported_pa_types[0],
    NULL,
    NULL,
    kdc_preauth_flags,
    kdc_include_padata,
    kdc_verify_preauth,
    kdc_return_preauth,
    NULL
};
#endif

plhandle
plugin_encrypted_challenge_pa_create()
{
        plhandle handle;
        plugin_pa* api = malloc(sizeof(plugin_pa));

        memset(api, 0, sizeof(plugin_pa));
        api->version = 1;
        api->server_init = _plugin_server_init;
        api->server_fini = _plugin_server_fini;
        api->preauth_flags = _plugin_preauth_flags;
        api->process_preauth = _plugin_process_preauth;
        api->kdc_include_padata = _plugin_kdc_include_padata;
        api->kdc_verify_preauth = _plugin_kdc_verify_preauth;
        api->kdc_return_preauth = _plugin_kdc_return_preauth;
        api->server_free_reqctx = _plugin_server_free_reqctx;
        handle.api = api;

        return handle;
}
