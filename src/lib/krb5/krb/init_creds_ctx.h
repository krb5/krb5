/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef KRB5_INIT_CREDS_CONTEXT
#define KRB5_INIT_CREDS_CONTEXT 1

struct _krb5_init_creds_context {
    krb5_gic_opt_ext *opte;
    char *in_tkt_service;
    krb5_prompter_fct prompter;
    void *prompter_data;
    krb5_gic_get_as_key_fct gak_fct;
    void *gak_data;
    krb5_timestamp request_time;
    krb5_deltat start_time;
    krb5_deltat tkt_life;
    krb5_deltat renew_life;
    krb5_boolean complete;
    unsigned int loopcount;
    krb5_data password;
    krb5_error *err_reply;
    krb5_creds cred;
    krb5_kdc_req *request;
    krb5_kdc_rep *reply;
    krb5_data *encoded_request_body;
    krb5_data *encoded_previous_request;
    struct krb5int_fast_request_state *fast_state;
    krb5_pa_data **preauth_to_use;
    krb5_data salt;
    krb5_data s2kparams;
    krb5_keyblock as_key;
    krb5_enctype etype;
    krb5_preauth_client_rock get_data_rock;
    krb5_boolean enc_pa_rep_permitted;
    krb5_boolean have_restarted;
    krb5_boolean sent_nontrivial_preauth;
};

krb5_error_code
krb5_get_as_key_password(krb5_context context,
                         krb5_principal client,
                         krb5_enctype etype,
                         krb5_prompter_fct prompter,
                         void *prompter_data,
                         krb5_data *salt,
                         krb5_data *params,
                         krb5_keyblock *as_key,
                         void *gak_data);

#endif /* !KRB5_INIT_CREDS_CONTEXT */
