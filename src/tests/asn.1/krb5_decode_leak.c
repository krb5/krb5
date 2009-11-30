/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * This program is intended to help detect memory leaks in the ASN.1
 * decoder functions by exercising their failure paths.  The setup
 * code for the test cases is copied from krb5_encode_test.c.
 *
 * This code does not actually detect leaks by itself; it must be run
 * through a leak-detection tool such as valgrind to do so.  Simply
 * running the program will exercise a bunch of ASN.1 encoder and
 * decoder code paths but won't validate the results.
 */

#include <stdio.h>
#include "k5-int.h"
#include "com_err.h"
#include "utility.h"

#include "ktest.h"
#include <string.h>

#include "debug.h"

krb5_context test_context;

/*
 * Contrary to our usual convention, krb5_free_cred_enc_part is a
 * contents-only free function (and is assumed to be by mk_cred and
 * rd_cred) and we have no whole-structure free function for that data
 * type.  So create one here.
 */
static void
free_cred_enc_part_whole(krb5_context ctx,
                         krb5_cred_enc_part *val)
{
    krb5_free_cred_enc_part(ctx, val);
    free(val);
}

int
main(int argc, char **argv)
{
    krb5_data *code;
    krb5_error_code retval;
    unsigned int i;

    retval = krb5_init_context(&test_context);
    if (retval) {
        com_err(argv[0], retval, "while initializing krb5");
        exit(1);
    }
    init_access(argv[0]);

#define setup(value, typestring, constructor)                           \
    retval = constructor(&(value));                                     \
    if (retval) {                                                       \
        com_err("krb5_decode_leak", retval, "while making sample %s",   \
                typestring);                                            \
        exit(1);                                                        \
    }

#define encode_run(value,type,typestring,description,encoder)

    /*
     * Encode a value.  Then attempt to trigger most failure paths of
     * the decoder function by passing in corrupt encodings, which we
     * generate by perturbing each byte of the encoding in turn.  Some
     * of the perturbed encodings are expected to decode successfully,
     * so we need a free function to discard successful results.  Make
     * sure to define a pointer named "tmp" of the correct type in the
     * enclosing block.
     */
#define leak_test(value, encoder, decoder, freefn)              \
    retval = encoder(&(value),&(code));                         \
    if (retval) {                                               \
        com_err("krb5_decode_leak", retval, "while encoding");  \
        exit(1);                                                \
    }                                                           \
    for (i = 0; i < code->length; i++) {                        \
        code->data[i] = (char)~((unsigned char)code->data[i]);  \
        retval = decoder(code, &tmp);                           \
        code->data[i] = (char)~((unsigned char)code->data[i]);  \
        if (retval == 0)                                        \
            freefn(test_context, tmp);                          \
    }                                                           \
    krb5_free_data(test_context, code);

    /****************************************************************/
    /* encode_krb5_authenticator */
    {
        krb5_authenticator authent, *tmp;

        setup(authent, "authenticator", ktest_make_sample_authenticator);
        leak_test(authent, encode_krb5_authenticator,
                  decode_krb5_authenticator, krb5_free_authenticator);

        ktest_destroy_checksum(&(authent.checksum));
        ktest_destroy_keyblock(&(authent.subkey));
        authent.seq_number = 0;
        ktest_empty_authorization_data(authent.authorization_data);
        leak_test(authent, encode_krb5_authenticator,
                  decode_krb5_authenticator, krb5_free_authenticator);

        ktest_destroy_authorization_data(&(authent.authorization_data));
        leak_test(authent, encode_krb5_authenticator,
                  decode_krb5_authenticator, krb5_free_authenticator);
        ktest_empty_authenticator(&authent);
    }

    /****************************************************************/
    /* encode_krb5_ticket */
    {
        krb5_ticket tkt, *tmp;

        setup(tkt, "ticket", ktest_make_sample_ticket);
        leak_test(tkt, encode_krb5_ticket, decode_krb5_ticket,
                  krb5_free_ticket);
        ktest_empty_ticket(&tkt);
    }

    /****************************************************************/
    /* encode_krb5_encryption_key */
    {
        krb5_keyblock keyblk, *tmp;

        setup(keyblk, "keyblock", ktest_make_sample_keyblock);
        leak_test(keyblk, encode_krb5_encryption_key,
                  decode_krb5_encryption_key, krb5_free_keyblock);
        ktest_empty_keyblock(&keyblk);
    }

    /****************************************************************/
    /* encode_krb5_enc_tkt_part */
    {
        krb5_ticket tkt;
        krb5_enc_tkt_part *tmp;

        memset(&tkt, 0, sizeof(krb5_ticket));
        tkt.enc_part2 = calloc(1, sizeof(krb5_enc_tkt_part));
        if (tkt.enc_part2 == NULL)
            com_err("allocating enc_tkt_part", errno, "");
        setup(*(tkt.enc_part2), "enc_tkt_part",
              ktest_make_sample_enc_tkt_part);

        leak_test(*(tkt.enc_part2), encode_krb5_enc_tkt_part,
                  decode_krb5_enc_tkt_part, krb5_free_enc_tkt_part);

        tkt.enc_part2->times.starttime = 0;
        tkt.enc_part2->times.renew_till = 0;
        ktest_destroy_address(&(tkt.enc_part2->caddrs[1]));
        ktest_destroy_address(&(tkt.enc_part2->caddrs[0]));
        ktest_destroy_authdata(&(tkt.enc_part2->authorization_data[1]));
        ktest_destroy_authdata(&(tkt.enc_part2->authorization_data[0]));

        /* ISODE version fails on the empty caddrs field */
        ktest_destroy_addresses(&(tkt.enc_part2->caddrs));
        ktest_destroy_authorization_data(&(tkt.enc_part2->authorization_data));

        leak_test(*(tkt.enc_part2), encode_krb5_enc_tkt_part,
                  decode_krb5_enc_tkt_part, krb5_free_enc_tkt_part);
        ktest_empty_ticket(&tkt);
    }

    /****************************************************************/
    /* encode_krb5_enc_kdc_rep_part */
    {
        krb5_kdc_rep kdcr;
        krb5_enc_kdc_rep_part *tmp;

        memset(&kdcr, 0, sizeof(kdcr));

        kdcr.enc_part2 = calloc(1, sizeof(krb5_enc_kdc_rep_part));
        if (kdcr.enc_part2 == NULL)
            com_err("allocating enc_kdc_rep_part", errno, "");
        setup(*(kdcr.enc_part2), "enc_kdc_rep_part",
              ktest_make_sample_enc_kdc_rep_part);

        leak_test(*(kdcr.enc_part2), encode_krb5_enc_kdc_rep_part,
                  decode_krb5_enc_kdc_rep_part, krb5_free_enc_kdc_rep_part);

        kdcr.enc_part2->key_exp = 0;
        kdcr.enc_part2->times.starttime = 0;
        kdcr.enc_part2->flags &= ~TKT_FLG_RENEWABLE;
        ktest_destroy_addresses(&(kdcr.enc_part2->caddrs));

        leak_test(*(kdcr.enc_part2), encode_krb5_enc_kdc_rep_part,
                  decode_krb5_enc_kdc_rep_part, krb5_free_enc_kdc_rep_part);

        ktest_empty_kdc_rep(&kdcr);
    }

    /****************************************************************/
    /* encode_krb5_as_rep */
    {
        krb5_kdc_rep kdcr, *tmp;

        setup(kdcr, "kdc_rep", ktest_make_sample_kdc_rep);
        kdcr.msg_type = KRB5_AS_REP;
        leak_test(kdcr, encode_krb5_as_rep, decode_krb5_as_rep,
                  krb5_free_kdc_rep);

        ktest_destroy_pa_data_array(&(kdcr.padata));
        leak_test(kdcr, encode_krb5_as_rep, decode_krb5_as_rep,
                  krb5_free_kdc_rep);

        ktest_empty_kdc_rep(&kdcr);

    }

    /****************************************************************/
    /* encode_krb5_tgs_rep */
    {
        krb5_kdc_rep kdcr, *tmp;

        setup(kdcr, "kdc_rep", ktest_make_sample_kdc_rep);
        kdcr.msg_type = KRB5_TGS_REP;
        leak_test(kdcr, encode_krb5_tgs_rep, decode_krb5_tgs_rep,
                  krb5_free_kdc_rep);

        ktest_destroy_pa_data_array(&(kdcr.padata));
        leak_test(kdcr, encode_krb5_tgs_rep, decode_krb5_tgs_rep,
                  krb5_free_kdc_rep);

        ktest_empty_kdc_rep(&kdcr);

    }

    /****************************************************************/
    /* encode_krb5_ap_req */
    {
        krb5_ap_req apreq, *tmp;

        setup(apreq, "ap_req", ktest_make_sample_ap_req);
        leak_test(apreq, encode_krb5_ap_req, decode_krb5_ap_req,
                  krb5_free_ap_req);
        ktest_empty_ap_req(&apreq);
    }

    /****************************************************************/
    /* encode_krb5_ap_rep */
    {
        krb5_ap_rep aprep, *tmp;

        setup(aprep, "ap_rep", ktest_make_sample_ap_rep);
        leak_test(aprep, encode_krb5_ap_rep, decode_krb5_ap_rep,
                  krb5_free_ap_rep);
        ktest_empty_ap_rep(&aprep);
    }

    /****************************************************************/
    /* encode_krb5_ap_rep_enc_part */
    {
        krb5_ap_rep_enc_part apenc, *tmp;

        setup(apenc, "ap_rep_enc_part", ktest_make_sample_ap_rep_enc_part);
        leak_test(apenc, encode_krb5_ap_rep_enc_part,
                  decode_krb5_ap_rep_enc_part, krb5_free_ap_rep_enc_part);

        ktest_destroy_keyblock(&(apenc.subkey));
        apenc.seq_number = 0;
        leak_test(apenc, encode_krb5_ap_rep_enc_part,
                  decode_krb5_ap_rep_enc_part, krb5_free_ap_rep_enc_part);
        ktest_empty_ap_rep_enc_part(&apenc);
    }

    /****************************************************************/
    /* encode_krb5_as_req */
    {
        krb5_kdc_req asreq, *tmp;

        setup(asreq, "kdc_req", ktest_make_sample_kdc_req);
        asreq.msg_type = KRB5_AS_REQ;
        asreq.kdc_options &= ~KDC_OPT_ENC_TKT_IN_SKEY;
        leak_test(asreq, encode_krb5_as_req, decode_krb5_as_req,
                  krb5_free_kdc_req);

        ktest_destroy_pa_data_array(&(asreq.padata));
        ktest_destroy_principal(&(asreq.client));
#ifndef ISODE_SUCKS
        ktest_destroy_principal(&(asreq.server));
#endif
        asreq.kdc_options |= KDC_OPT_ENC_TKT_IN_SKEY;
        asreq.from = 0;
        asreq.rtime = 0;
        ktest_destroy_addresses(&(asreq.addresses));
        ktest_destroy_enc_data(&(asreq.authorization_data));
        leak_test(asreq, encode_krb5_as_req, decode_krb5_as_req,
                  krb5_free_kdc_req);

        ktest_destroy_sequence_of_ticket(&(asreq.second_ticket));
#ifndef ISODE_SUCKS
        ktest_make_sample_principal(&(asreq.server));
#endif
        asreq.kdc_options &= ~KDC_OPT_ENC_TKT_IN_SKEY;
        leak_test(asreq, encode_krb5_as_req, decode_krb5_as_req,
                  krb5_free_kdc_req);
        ktest_empty_kdc_req(&asreq);
    }

    /****************************************************************/
    /* encode_krb5_tgs_req */
    {
        krb5_kdc_req tgsreq, *tmp;

        setup(tgsreq, "kdc_req", ktest_make_sample_kdc_req);
        tgsreq.msg_type = KRB5_TGS_REQ;
        tgsreq.kdc_options &= ~KDC_OPT_ENC_TKT_IN_SKEY;
        leak_test(tgsreq, encode_krb5_tgs_req, decode_krb5_tgs_req,
                  krb5_free_kdc_req);

        ktest_destroy_pa_data_array(&(tgsreq.padata));
        ktest_destroy_principal(&(tgsreq.client));
#ifndef ISODE_SUCKS
        ktest_destroy_principal(&(tgsreq.server));
#endif
        tgsreq.kdc_options |= KDC_OPT_ENC_TKT_IN_SKEY;
        tgsreq.from = 0;
        tgsreq.rtime = 0;
        ktest_destroy_addresses(&(tgsreq.addresses));
        ktest_destroy_enc_data(&(tgsreq.authorization_data));
        leak_test(tgsreq, encode_krb5_tgs_req, decode_krb5_tgs_req,
                  krb5_free_kdc_req);

        ktest_destroy_sequence_of_ticket(&(tgsreq.second_ticket));
#ifndef ISODE_SUCKS
        ktest_make_sample_principal(&(tgsreq.server));
#endif
        tgsreq.kdc_options &= ~KDC_OPT_ENC_TKT_IN_SKEY;
        leak_test(tgsreq, encode_krb5_tgs_req, decode_krb5_tgs_req,
                  krb5_free_kdc_req);
        ktest_empty_kdc_req(&tgsreq);
    }

    /****************************************************************/
    /* encode_krb5_kdc_req_body */
    {
        krb5_kdc_req kdcrb, *tmp;

        memset(&kdcrb, 0, sizeof(kdcrb));
        setup(kdcrb, "kdc_req_body", ktest_make_sample_kdc_req_body);
        kdcrb.kdc_options &= ~KDC_OPT_ENC_TKT_IN_SKEY;
        leak_test(kdcrb, encode_krb5_kdc_req_body, decode_krb5_kdc_req_body,
                  krb5_free_kdc_req);

        ktest_destroy_principal(&(kdcrb.client));
#ifndef ISODE_SUCKS
        ktest_destroy_principal(&(kdcrb.server));
#endif
        kdcrb.kdc_options |= KDC_OPT_ENC_TKT_IN_SKEY;
        kdcrb.from = 0;
        kdcrb.rtime = 0;
        ktest_destroy_addresses(&(kdcrb.addresses));
        ktest_destroy_enc_data(&(kdcrb.authorization_data));
        leak_test(kdcrb, encode_krb5_kdc_req_body, decode_krb5_kdc_req_body,
                  krb5_free_kdc_req);

        ktest_destroy_sequence_of_ticket(&(kdcrb.second_ticket));
#ifndef ISODE_SUCKS
        ktest_make_sample_principal(&(kdcrb.server));
#endif
        kdcrb.kdc_options &= ~KDC_OPT_ENC_TKT_IN_SKEY;
        leak_test(kdcrb, encode_krb5_kdc_req_body, decode_krb5_kdc_req_body,
                  krb5_free_kdc_req);
        ktest_empty_kdc_req(&kdcrb);
    }

    /****************************************************************/
    /* encode_krb5_safe */
    {
        krb5_safe s, *tmp;

        setup(s, "safe", ktest_make_sample_safe);
        leak_test(s, encode_krb5_safe, decode_krb5_safe, krb5_free_safe);

        s.timestamp = 0;
        /* s.usec should be opted out by the timestamp */
        s.seq_number = 0;
        ktest_destroy_address(&(s.r_address));
        leak_test(s, encode_krb5_safe, decode_krb5_safe, krb5_free_safe);
        ktest_empty_safe(&s);
    }

    /****************************************************************/
    /* encode_krb5_priv */
    {
        krb5_priv p, *tmp;

        setup(p, "priv", ktest_make_sample_priv);
        leak_test(p, encode_krb5_priv, decode_krb5_priv, krb5_free_priv);
        ktest_empty_priv(&p);
    }

    /****************************************************************/
    /* encode_krb5_enc_priv_part */
    {
        krb5_priv_enc_part ep, *tmp;

        setup(ep, "priv_enc_part", ktest_make_sample_priv_enc_part);
        leak_test(ep, encode_krb5_enc_priv_part, decode_krb5_enc_priv_part,
                  krb5_free_priv_enc_part);

        ep.timestamp = 0;
        /* ep.usec should be opted out along with timestamp */
        ep.seq_number = 0;
        ktest_destroy_address(&(ep.r_address));
        leak_test(ep, encode_krb5_enc_priv_part, decode_krb5_enc_priv_part,
                  krb5_free_priv_enc_part);
        ktest_empty_priv_enc_part(&ep);
    }

    /****************************************************************/
    /* encode_krb5_cred */
    {
        krb5_cred c, *tmp;

        setup(c, "cred", ktest_make_sample_cred);
        leak_test(c, encode_krb5_cred, decode_krb5_cred, krb5_free_cred);
        ktest_empty_cred(&c);
    }

    /****************************************************************/
    /* encode_krb5_enc_cred_part */
    {
        krb5_cred_enc_part cep, *tmp;

        setup(cep, "cred_enc_part", ktest_make_sample_cred_enc_part);
        leak_test(cep, encode_krb5_enc_cred_part, decode_krb5_enc_cred_part,
                  free_cred_enc_part_whole);

        ktest_destroy_principal(&(cep.ticket_info[0]->client));
        ktest_destroy_principal(&(cep.ticket_info[0]->server));
        cep.ticket_info[0]->flags = 0;
        cep.ticket_info[0]->times.authtime = 0;
        cep.ticket_info[0]->times.starttime = 0;
        cep.ticket_info[0]->times.endtime = 0;
        cep.ticket_info[0]->times.renew_till = 0;
        ktest_destroy_addresses(&(cep.ticket_info[0]->caddrs));
        cep.nonce = 0;
        cep.timestamp = 0;
        ktest_destroy_address(&(cep.s_address));
        ktest_destroy_address(&(cep.r_address));
        leak_test(cep, encode_krb5_enc_cred_part, decode_krb5_enc_cred_part,
                  free_cred_enc_part_whole);
        ktest_empty_cred_enc_part(&cep);
    }

    /****************************************************************/
    /* encode_krb5_error */
    {
        krb5_error kerr, *tmp;

        setup(kerr, "error", ktest_make_sample_error);
        leak_test(kerr, encode_krb5_error, decode_krb5_error, krb5_free_error);

        kerr.ctime = 0;
        ktest_destroy_principal(&(kerr.client));
        ktest_empty_data(&(kerr.text));
        ktest_empty_data(&(kerr.e_data));
        leak_test(kerr, encode_krb5_error, decode_krb5_error, krb5_free_error);

        ktest_empty_error(&kerr);
    }

    /****************************************************************/
    /* encode_krb5_authdata */
    {
        krb5_authdata **ad, **tmp;

        setup(ad, "authorization_data", ktest_make_sample_authorization_data);
        leak_test(*ad, encode_krb5_authdata, decode_krb5_authdata,
                  krb5_free_authdata);
        ktest_destroy_authorization_data(&ad);
    }

    /****************************************************************/
    /* encode_pwd_sequence */
    {
        passwd_phrase_element ppe, *tmp;

        setup(ppe, "PasswdSequence", ktest_make_sample_passwd_phrase_element);
        leak_test(ppe, encode_krb5_pwd_sequence, decode_krb5_pwd_sequence,
                  krb5_free_passwd_phrase_element);
        ktest_empty_passwd_phrase_element(&ppe);
    }

    /****************************************************************/
    /* encode_passwd_data */
    {
        krb5_pwd_data pd, *tmp;

        setup(pd, "PasswdData", ktest_make_sample_krb5_pwd_data);
        leak_test(pd, encode_krb5_pwd_data, decode_krb5_pwd_data,
                  krb5_free_pwd_data);
        ktest_empty_pwd_data(&pd);
    }

    /****************************************************************/
    /* encode_padata_sequence */
    {
        krb5_pa_data **pa, **tmp;

        setup(pa, "PreauthData", ktest_make_sample_pa_data_array);
        leak_test(*pa, encode_krb5_padata_sequence,
                  decode_krb5_padata_sequence, krb5_free_pa_data);
        ktest_destroy_pa_data_array(&pa);
    }

    /****************************************************************/
    /* encode_padata_sequence (empty) */
    {
        krb5_pa_data **pa, **tmp;

        setup(pa,"EmptyPreauthData",ktest_make_sample_empty_pa_data_array);
        leak_test(*pa, encode_krb5_padata_sequence,
                  decode_krb5_padata_sequence, krb5_free_pa_data);
        ktest_destroy_pa_data_array(&pa);
    }

    /****************************************************************/
    /* encode_alt_method */
    {
        krb5_alt_method am, *tmp;

        setup(am, "AltMethod", ktest_make_sample_alt_method);
        leak_test(am, encode_krb5_alt_method, decode_krb5_alt_method,
                  krb5_free_alt_method);
        am.length = 0;
        if (am.data)
            free(am.data);
        am.data = 0;
        leak_test(am, encode_krb5_alt_method, decode_krb5_alt_method,
                  krb5_free_alt_method);
        ktest_empty_alt_method(&am);
    }

    /****************************************************************/
    /* encode_etype_info */
    {
        krb5_etype_info_entry **info, **tmp;

        setup(info, "etype_info", ktest_make_sample_etype_info);
        leak_test(*info, encode_krb5_etype_info, decode_krb5_etype_info,
                  krb5_free_etype_info);

        ktest_destroy_etype_info_entry(info[2]);      info[2] = 0;
        ktest_destroy_etype_info_entry(info[1]);      info[1] = 0;
        leak_test(*info, encode_krb5_etype_info, decode_krb5_etype_info,
                  krb5_free_etype_info);

        ktest_destroy_etype_info_entry(info[0]);      info[0] = 0;
        leak_test(*info, encode_krb5_etype_info, decode_krb5_etype_info,
                  krb5_free_etype_info);

        ktest_destroy_etype_info(info);
    }

    /* encode_etype_info 2*/
    {
        krb5_etype_info_entry **info, **tmp;

        setup(info, "etype_info2", ktest_make_sample_etype_info2);
        leak_test(*info, encode_krb5_etype_info2, decode_krb5_etype_info2,
                  krb5_free_etype_info);

        ktest_destroy_etype_info_entry(info[2]);      info[2] = 0;
        ktest_destroy_etype_info_entry(info[1]);      info[1] = 0;
        leak_test(*info, encode_krb5_etype_info2, decode_krb5_etype_info2,
                  krb5_free_etype_info);

        ktest_destroy_etype_info(info);
    }

    /****************************************************************/
    /* encode_pa_enc_ts */
    {
        krb5_pa_enc_ts pa_enc, *tmp;

        setup(pa_enc, "pa_enc_ts", ktest_make_sample_pa_enc_ts);
        leak_test(pa_enc, encode_krb5_pa_enc_ts, decode_krb5_pa_enc_ts,
                  krb5_free_pa_enc_ts);
        pa_enc.pausec = 0;
        leak_test(pa_enc, encode_krb5_pa_enc_ts, decode_krb5_pa_enc_ts,
                  krb5_free_pa_enc_ts);
    }

    /****************************************************************/
    /* encode_enc_data */
    {
        krb5_enc_data enc_data, *tmp;

        setup(enc_data, "enc_data", ktest_make_sample_enc_data);
        leak_test(enc_data, encode_krb5_enc_data, decode_krb5_enc_data,
                  krb5_free_enc_data);
        ktest_destroy_enc_data(&enc_data);
    }
    /****************************************************************/
    /* encode_krb5_sam_challenge */
    {
        krb5_sam_challenge sam_ch, *tmp;

        setup(sam_ch, "sam_challenge", ktest_make_sample_sam_challenge);
        leak_test(sam_ch, encode_krb5_sam_challenge, decode_krb5_sam_challenge,
                  krb5_free_sam_challenge);
        ktest_empty_sam_challenge(&sam_ch);
    }
    /****************************************************************/
    /* encode_krb5_sam_response */
    {
        krb5_sam_response sam_ch, *tmp;

        setup(sam_ch, "sam_response", ktest_make_sample_sam_response);
        leak_test(sam_ch, encode_krb5_sam_response, decode_krb5_sam_response,
                  krb5_free_sam_response);
        ktest_empty_sam_response(&sam_ch);
    }
    /****************************************************************/
    /* encode_krb5_enc_sam_response_enc */
    {
        krb5_enc_sam_response_enc sam_ch, *tmp;

        setup(sam_ch, "enc_sam_response_enc",
              ktest_make_sample_enc_sam_response_enc);
        leak_test(sam_ch, encode_krb5_enc_sam_response_enc,
                  decode_krb5_enc_sam_response_enc,
                  krb5_free_enc_sam_response_enc);
        ktest_empty_enc_sam_response_enc(&sam_ch);
    }
    /****************************************************************/
    /* encode_krb5_predicted_sam_response */
    {
        krb5_predicted_sam_response sam_ch, *tmp;

        setup(sam_ch, "predicted_sam_response",
              ktest_make_sample_predicted_sam_response);
        leak_test(sam_ch, encode_krb5_predicted_sam_response,
                  decode_krb5_predicted_sam_response,
                  krb5_free_predicted_sam_response);
        ktest_empty_predicted_sam_response(&sam_ch);
    }
    /****************************************************************/
    /* encode_krb5_sam_response_2 */
    {
        krb5_sam_response_2 sam_ch2, *tmp;

        setup(sam_ch2, "sam_response_2", ktest_make_sample_sam_response_2);
        leak_test(sam_ch2, encode_krb5_sam_response_2,
                  decode_krb5_sam_response_2, krb5_free_sam_response_2);
        ktest_empty_sam_response_2(&sam_ch2);
    }
    /****************************************************************/
    /* encode_krb5_sam_response_enc_2 */
    {
        krb5_enc_sam_response_enc_2 sam_ch2, *tmp;

        setup(sam_ch2, "enc_sam_response_enc_2",
              ktest_make_sample_enc_sam_response_enc_2);
        leak_test(sam_ch2, encode_krb5_enc_sam_response_enc_2,
                  decode_krb5_enc_sam_response_enc_2,
                  krb5_free_enc_sam_response_enc_2);
        ktest_empty_enc_sam_response_enc_2(&sam_ch2);
    }
    /****************************************************************/
    /* encode_krb5_pa_s4u_x509_user */
    {
        krb5_pa_s4u_x509_user s4u, *tmp;
        setup(s4u, "pa_s4u_x509_user",
              ktest_make_sample_pa_s4u_x509_user);
        leak_test(s4u, encode_krb5_pa_s4u_x509_user,
                  decode_krb5_pa_s4u_x509_user,
                  krb5_free_pa_s4u_x509_user);
        ktest_empty_pa_s4u_x509_user(&s4u);
    }
    /****************************************************************/
    /* encode_krb5_ad_kdcissued */
    {
        krb5_ad_kdcissued kdci, *tmp;
        setup(kdci, "ad_kdcissued",
              ktest_make_sample_ad_kdcissued);
        leak_test(kdci, encode_krb5_ad_kdcissued,
                  decode_krb5_ad_kdcissued,
                  krb5_free_ad_kdcissued);
        ktest_empty_ad_kdcissued(&kdci);
    }
#if 0
    /****************************************************************/
    /* encode_krb5_ad_signedpath_data */
    {
        krb5_ad_signedpath_data spd, *tmp;
        setup(spd, "ad_signedpath_data",
              ktest_make_sample_ad_signedpath_data);
        leak_test(spd, encode_krb5_ad_signedpath_data,
                  decode_krb5_ad_signedpath_data,
                  NULL);
        ktest_empty_ad_signedpath_data(&spd);
    }
#endif
    /****************************************************************/
    /* encode_krb5_ad_signedpath */
    {
        krb5_ad_signedpath sp, *tmp;
        setup(sp, "ad_signedpath",
              ktest_make_sample_ad_signedpath);
        leak_test(sp, encode_krb5_ad_signedpath,
                  decode_krb5_ad_signedpath,
                  krb5_free_ad_signedpath);
        ktest_empty_ad_signedpath(&sp);
    }
    krb5_free_context(test_context);
    return 0;
}
