/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * kdc/do_tgs_req.c
 *
 * Copyright 1990,1991,2001,2007,2008,2009 by the Massachusetts Institute of Technology.
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
 *
 *
 * KDC Routines to deal with TGS_REQ's
 */
/*
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"

#include <syslog.h>
#ifdef HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif
#endif

#include "kdc_util.h"
#include "policy.h"
#include "extern.h"
#include "adm_proto.h"
#include <ctype.h>

static void
find_alternate_tgs(krb5_kdc_req *,krb5_db_entry *,
                   krb5_boolean *,int *);

static krb5_error_code
prepare_error_tgs(struct kdc_request_state *, krb5_kdc_req *,krb5_ticket *,int,
                  krb5_principal,krb5_data **,const char *, krb5_data *);

static krb5_int32
prep_reprocess_req(krb5_kdc_req *,krb5_principal *);

/*ARGSUSED*/
krb5_error_code
process_tgs_req(krb5_data *pkt, const krb5_fulladdr *from,
                krb5_data **response)
{
    krb5_keyblock * subkey = 0;
    krb5_keyblock * tgskey = 0;
    krb5_kdc_req *request = 0;
    krb5_db_entry server;
    krb5_kdc_rep reply;
    krb5_enc_kdc_rep_part reply_encpart;
    krb5_ticket ticket_reply, *header_ticket = 0;
    int st_idx = 0;
    krb5_enc_tkt_part enc_tkt_reply;
    krb5_transited enc_tkt_transited;
    int newtransited = 0;
    krb5_error_code retval = 0;
    krb5_keyblock encrypting_key;
    int nprincs = 0;
    krb5_boolean more;
    krb5_timestamp kdc_time, authtime = 0;
    krb5_keyblock session_key;
    krb5_timestamp rtime;
    krb5_keyblock *reply_key = NULL;
    krb5_keyblock *mkey_ptr;
    krb5_key_data  *server_key;
    char *cname = 0, *sname = 0, *altcname = 0;
    krb5_last_req_entry *nolrarray[2], nolrentry;
    krb5_enctype useenctype;
    int errcode, errcode2;
    register int i;
    int firstpass = 1;
    const char        *status = 0;
    krb5_enc_tkt_part *header_enc_tkt = NULL; /* TGT */
    krb5_enc_tkt_part *subject_tkt = NULL; /* TGT or evidence ticket */
    krb5_db_entry client, krbtgt;
    int c_nprincs = 0, k_nprincs = 0;
    krb5_pa_s4u_x509_user *s4u_x509_user = NULL; /* protocol transition request */
    krb5_authdata **kdc_issued_auth_data = NULL; /* auth data issued by KDC */
    unsigned int c_flags = 0, s_flags = 0;       /* client/server KDB flags */
    char *s4u_name = NULL;
    krb5_boolean is_referral, db_ref_done = FALSE;
    const char *emsg = NULL;
    krb5_data *tgs_1 =NULL, *server_1 = NULL;
    krb5_principal krbtgt_princ;
    krb5_kvno ticket_kvno = 0;
    struct kdc_request_state *state = NULL;
    krb5_pa_data *pa_tgs_req; /*points into request*/
    krb5_data scratch;
    krb5_data e_data = empty_data(); /* backend-provided error data */

    reply.padata = 0; /* For cleanup handler */
    reply_encpart.enc_padata = 0;
    enc_tkt_reply.authorization_data = NULL;
    e_data.data = NULL;

    session_key.contents = NULL;

    retval = decode_krb5_tgs_req(pkt, &request);
    if (retval)
        return retval;
    if (request->msg_type != KRB5_TGS_REQ) {
        krb5_free_kdc_req(kdc_context, request);
        return KRB5_BADMSGTYPE;
    }

    /*
     * setup_server_realm() sets up the global realm-specific data pointer.
     */
    if ((retval = setup_server_realm(request->server))) {
        krb5_free_kdc_req(kdc_context, request);
        return retval;
    }
    errcode = kdc_process_tgs_req(request, from, pkt, &header_ticket,
                                  &krbtgt, &k_nprincs, &tgskey,
                                  &subkey, &pa_tgs_req);
    if (header_ticket && header_ticket->enc_part2 &&
        (errcode2 = krb5_unparse_name(kdc_context,
                                      header_ticket->enc_part2->client,
                                      &cname))) {
        status = "UNPARSING CLIENT";
        errcode = errcode2;
        goto cleanup;
    }
    limit_string(cname);

    if (errcode) {
        status = "PROCESS_TGS";
        goto cleanup;
    }

    if (!header_ticket) {
        errcode = KRB5_NO_TKT_SUPPLIED;        /* XXX? */
        status="UNEXPECTED NULL in header_ticket";
        goto cleanup;
    }
    errcode = kdc_make_rstate(&state);
    if (errcode !=0) {
        status = "making state";
        goto cleanup;
    }
    scratch.length = pa_tgs_req->length;
    scratch.data = (char *) pa_tgs_req->contents;
    errcode = kdc_find_fast(&request, &scratch, subkey,
                            header_ticket->enc_part2->session, state);
    if (errcode !=0) {
        status = "kdc_find_fast";
        goto cleanup;
    }

    /*
     * Pointer to the encrypted part of the header ticket, which may be
     * replaced to point to the encrypted part of the evidence ticket
     * if constrained delegation is used. This simplifies the number of
     * special cases for constrained delegation.
     */
    header_enc_tkt = header_ticket->enc_part2;

    /*
     * We've already dealt with the AP_REQ authentication, so we can
     * use header_ticket freely.  The encrypted part (if any) has been
     * decrypted with the session key.
     */

    /* XXX make sure server here has the proper realm...taken from AP_REQ
       header? */

    if (isflagset(request->kdc_options, KDC_OPT_CANONICALIZE)) {
        setflag(c_flags, KRB5_KDB_FLAG_CANONICALIZE);
        setflag(s_flags, KRB5_KDB_FLAG_CANONICALIZE);
    }

    db_ref_done = FALSE;
ref_tgt_again:
    nprincs = 1;
    if ((errcode = krb5_unparse_name(kdc_context, request->server, &sname))) {
        status = "UNPARSING SERVER";
        goto cleanup;
    }
    limit_string(sname);

    errcode = krb5_db_get_principal_ext(kdc_context,
                                        request->server,
                                        s_flags,
                                        &server,
                                        &nprincs,
                                        &more);
    if (errcode) {
        status = "LOOKING_UP_SERVER";
        nprincs = 0;
        goto cleanup;
    }
tgt_again:
    if (more) {
        status = "NON_UNIQUE_PRINCIPAL";
        errcode = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
        goto cleanup;
    } else if (nprincs != 1) {
        /*
         * might be a request for a TGT for some other realm; we
         * should do our best to find such a TGS in this db
         */
        if (firstpass ) {

            if ( krb5_is_tgs_principal(request->server) == TRUE) {
                /* Principal is a name of krb ticket service */
                if (krb5_princ_size(kdc_context, request->server) == 2) {

                    server_1 = krb5_princ_component(kdc_context,
                                                    request->server, 1);
                    tgs_1 = krb5_princ_component(kdc_context, tgs_server, 1);

                    if (!tgs_1 || !data_eq(*server_1, *tgs_1)) {
                        krb5_db_free_principal(kdc_context, &server, nprincs);
                        find_alternate_tgs(request, &server, &more, &nprincs);
                        firstpass = 0;
                        goto tgt_again;
                    }
                }
                krb5_db_free_principal(kdc_context, &server, nprincs);
                status = "UNKNOWN_SERVER";
                errcode = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
                goto cleanup;

            } else if ( db_ref_done == FALSE) {
                retval = prep_reprocess_req(request, &krbtgt_princ);
                if (!retval) {
                    krb5_free_principal(kdc_context, request->server);
                    retval = krb5_copy_principal(kdc_context, krbtgt_princ,
                                                 &(request->server));
                    if (!retval) {
                        db_ref_done = TRUE;
                        if (sname != NULL)
                            free(sname);
                        goto ref_tgt_again;
                    }
                }
            }
        }

        krb5_db_free_principal(kdc_context, &server, nprincs);
        status = "UNKNOWN_SERVER";
        errcode = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
        goto cleanup;
    }

    if ((errcode = krb5_timeofday(kdc_context, &kdc_time))) {
        status = "TIME_OF_DAY";
        goto cleanup;
    }

    if ((retval = validate_tgs_request(request, server, header_ticket,
                                       kdc_time, &status, &e_data))) {
        if (!status)
            status = "UNKNOWN_REASON";
        errcode = retval + ERROR_TABLE_BASE_krb5;
        goto cleanup;
    }

    if (!is_local_principal(header_enc_tkt->client))
        setflag(c_flags, KRB5_KDB_FLAG_CROSS_REALM);

    is_referral = krb5_is_tgs_principal(server.princ) &&
        !krb5_principal_compare(kdc_context, tgs_server, server.princ);

    /* Check for protocol transition */
    errcode = kdc_process_s4u2self_req(kdc_context,
                                       request,
                                       header_enc_tkt->client,
                                       &server,
                                       subkey,
                                       header_enc_tkt->session,
                                       kdc_time,
                                       &s4u_x509_user,
                                       &client,
                                       &c_nprincs,
                                       &status);
    if (errcode)
        goto cleanup;
    if (s4u_x509_user != NULL)
        setflag(c_flags, KRB5_KDB_FLAG_PROTOCOL_TRANSITION);

    /*
     * We pick the session keytype here....
     *
     * Some special care needs to be taken in the user-to-user
     * case, since we don't know what keytypes the application server
     * which is doing user-to-user authentication can support.  We
     * know that it at least must be able to support the encryption
     * type of the session key in the TGT, since otherwise it won't be
     * able to decrypt the U2U ticket!  So we use that in preference
     * to anything else.
     */
    useenctype = 0;
    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY |
                  KDC_OPT_CNAME_IN_ADDL_TKT)) {
        krb5_keyblock  * st_sealing_key;
        krb5_kvno        st_srv_kvno;
        krb5_enctype     etype;
        krb5_db_entry    st_client;
        int              st_nprincs = 0;

        /*
         * Get the key for the second ticket, and decrypt it.
         */
        if ((errcode = kdc_get_server_key(request->second_ticket[st_idx],
                                          c_flags,
                                          TRUE, /* match_enctype */
                                          &st_client,
                                          &st_nprincs,
                                          &st_sealing_key,
                                          &st_srv_kvno))) {
            status = "2ND_TKT_SERVER";
            goto cleanup;
        }
        errcode = krb5_decrypt_tkt_part(kdc_context, st_sealing_key,
                                        request->second_ticket[st_idx]);
        krb5_free_keyblock(kdc_context, st_sealing_key);
        if (errcode) {
            status = "2ND_TKT_DECRYPT";
            krb5_db_free_principal(kdc_context, &st_client, st_nprincs);
            goto cleanup;
        }

        etype = request->second_ticket[st_idx]->enc_part2->session->enctype;
        if (!krb5_c_valid_enctype(etype)) {
            status = "BAD_ETYPE_IN_2ND_TKT";
            errcode = KRB5KDC_ERR_ETYPE_NOSUPP;
            krb5_db_free_principal(kdc_context, &st_client, st_nprincs);
            goto cleanup;
        }

        for (i = 0; i < request->nktypes; i++) {
            if (request->ktype[i] == etype) {
                useenctype = etype;
                break;
            }
        }

        if (isflagset(request->kdc_options, KDC_OPT_CNAME_IN_ADDL_TKT)) {
            /* Do constrained delegation protocol and authorization checks */
            errcode = kdc_process_s4u2proxy_req(kdc_context,
                                                request,
                                                request->second_ticket[st_idx]->enc_part2,
                                                &st_client,
                                                header_ticket->enc_part2->client,
                                                request->server,
                                                &status);
            if (errcode)
                goto cleanup;

            setflag(c_flags, KRB5_KDB_FLAG_CONSTRAINED_DELEGATION);

            assert(krb5_is_tgs_principal(header_ticket->server));

            assert(c_nprincs == 0); /* assured by kdc_process_s4u2self_req() */

            client = st_client;
            c_nprincs = st_nprincs;
        } else {
            /* "client" is not used for user2user */
            krb5_db_free_principal(kdc_context, &st_client, st_nprincs);
        }
    }

    /*
     * Select the keytype for the ticket session key.
     */
    if ((useenctype == 0) &&
        (useenctype = select_session_keytype(kdc_context, &server,
                                             request->nktypes,
                                             request->ktype)) == 0) {
        /* unsupported ktype */
        status = "BAD_ENCRYPTION_TYPE";
        errcode = KRB5KDC_ERR_ETYPE_NOSUPP;
        goto cleanup;
    }

    errcode = krb5_c_make_random_key(kdc_context, useenctype, &session_key);

    if (errcode) {
        /* random key failed */
        status = "RANDOM_KEY_FAILED";
        goto cleanup;
    }

    /*
     * subject_tkt will refer to the evidence ticket (for constrained
     * delegation) or the TGT. The distinction from header_enc_tkt is
     * necessary because the TGS signature only protects some fields:
     * the others could be forged by a malicious server.
     */

    if (isflagset(c_flags, KRB5_KDB_FLAG_CONSTRAINED_DELEGATION))
        subject_tkt = request->second_ticket[st_idx]->enc_part2;
    else
        subject_tkt = header_enc_tkt;
    authtime = subject_tkt->times.authtime;

    if (is_referral)
        ticket_reply.server = server.princ;
    else
        ticket_reply.server = request->server; /* XXX careful for realm... */

    enc_tkt_reply.flags = 0;
    enc_tkt_reply.times.starttime = 0;

    if (isflagset(server.attributes, KRB5_KDB_OK_AS_DELEGATE))
        setflag(enc_tkt_reply.flags, TKT_FLG_OK_AS_DELEGATE);

    /*
     * Fix header_ticket's starttime; if it's zero, fill in the
     * authtime's value.
     */
    if (!(header_enc_tkt->times.starttime))
        header_enc_tkt->times.starttime = authtime;
    setflag(enc_tkt_reply.flags, TKT_FLG_ENC_PA_REP);

    /* don't use new addresses unless forwarded, see below */

    enc_tkt_reply.caddrs = header_enc_tkt->caddrs;
    /* noaddrarray[0] = 0; */
    reply_encpart.caddrs = 0;/* optional...don't put it in */
    reply_encpart.enc_padata = NULL;

    /*
     * It should be noted that local policy may affect the
     * processing of any of these flags.  For example, some
     * realms may refuse to issue renewable tickets
     */

    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE)) {
        setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);

        if (isflagset(c_flags, KRB5_KDB_FLAG_PROTOCOL_TRANSITION)) {
            /*
             * If S4U2Self principal is not forwardable, then mark ticket as
             * unforwardable. This behaviour matches Windows, but it is
             * different to the MIT AS-REQ path, which returns an error
             * (KDC_ERR_POLICY) if forwardable tickets cannot be issued.
             *
             * Consider this block the S4U2Self equivalent to
             * validate_forwardable().
             */
            if (c_nprincs &&
                isflagset(client.attributes, KRB5_KDB_DISALLOW_FORWARDABLE))
                clear(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);
            /*
             * Forwardable flag is propagated along referral path.
             */
            else if (!isflagset(header_enc_tkt->flags, TKT_FLG_FORWARDABLE))
                clear(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);
            /*
             * OK_TO_AUTH_AS_DELEGATE must be set on the service requesting
             * S4U2Self in order for forwardable tickets to be returned.
             */
            else if (!is_referral &&
                     !isflagset(server.attributes,
                                KRB5_KDB_OK_TO_AUTH_AS_DELEGATE))
                clear(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);
        }
    }

    if (isflagset(request->kdc_options, KDC_OPT_FORWARDED)) {
        setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDED);

        /* include new addresses in ticket & reply */

        enc_tkt_reply.caddrs = request->addresses;
        reply_encpart.caddrs = request->addresses;
    }
    if (isflagset(header_enc_tkt->flags, TKT_FLG_FORWARDED))
        setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDED);

    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE))
        setflag(enc_tkt_reply.flags, TKT_FLG_PROXIABLE);

    if (isflagset(request->kdc_options, KDC_OPT_PROXY)) {
        setflag(enc_tkt_reply.flags, TKT_FLG_PROXY);

        /* include new addresses in ticket & reply */

        enc_tkt_reply.caddrs = request->addresses;
        reply_encpart.caddrs = request->addresses;
    }

    if (isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE))
        setflag(enc_tkt_reply.flags, TKT_FLG_MAY_POSTDATE);

    if (isflagset(request->kdc_options, KDC_OPT_POSTDATED)) {
        setflag(enc_tkt_reply.flags, TKT_FLG_POSTDATED);
        setflag(enc_tkt_reply.flags, TKT_FLG_INVALID);
        enc_tkt_reply.times.starttime = request->from;
    } else
        enc_tkt_reply.times.starttime = kdc_time;

    if (isflagset(request->kdc_options, KDC_OPT_VALIDATE)) {
        assert(isflagset(c_flags, KRB5_KDB_FLAGS_S4U) == 0);
        /* BEWARE of allocation hanging off of ticket & enc_part2, it belongs
           to the caller */
        ticket_reply = *(header_ticket);
        enc_tkt_reply = *(header_ticket->enc_part2);
        enc_tkt_reply.authorization_data = NULL;
        clear(enc_tkt_reply.flags, TKT_FLG_INVALID);
    }

    if (isflagset(request->kdc_options, KDC_OPT_RENEW)) {
        krb5_deltat old_life;

        assert(isflagset(c_flags, KRB5_KDB_FLAGS_S4U) == 0);
        /* BEWARE of allocation hanging off of ticket & enc_part2, it belongs
           to the caller */
        ticket_reply = *(header_ticket);
        enc_tkt_reply = *(header_ticket->enc_part2);
        enc_tkt_reply.authorization_data = NULL;

        old_life = enc_tkt_reply.times.endtime - enc_tkt_reply.times.starttime;

        enc_tkt_reply.times.starttime = kdc_time;
        enc_tkt_reply.times.endtime =
            min(header_ticket->enc_part2->times.renew_till,
                kdc_time + old_life);
    } else {
        /* not a renew request */
        enc_tkt_reply.times.starttime = kdc_time;

        kdc_get_ticket_endtime(kdc_context,
                               enc_tkt_reply.times.starttime,
                               header_enc_tkt->times.endtime,
                               request->till,
                               &client,
                               &server,
                               &enc_tkt_reply.times.endtime);

        if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE_OK) &&
            (enc_tkt_reply.times.endtime < request->till) &&
            isflagset(header_enc_tkt->flags, TKT_FLG_RENEWABLE)) {
            setflag(request->kdc_options, KDC_OPT_RENEWABLE);
            request->rtime =
                min(request->till, header_enc_tkt->times.renew_till);
        }
    }
    rtime = (request->rtime == 0) ? kdc_infinity : request->rtime;

    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE)) {
        /* already checked above in policy check to reject request for a
           renewable ticket using a non-renewable ticket */
        setflag(enc_tkt_reply.flags, TKT_FLG_RENEWABLE);
        enc_tkt_reply.times.renew_till =
            min(rtime,
                min(header_enc_tkt->times.renew_till,
                    enc_tkt_reply.times.starttime +
                    min(server.max_renewable_life,
                        max_renewable_life_for_realm)));
    } else {
        enc_tkt_reply.times.renew_till = 0;
    }
    if (isflagset(header_enc_tkt->flags, TKT_FLG_ANONYMOUS))
        setflag(enc_tkt_reply.flags, TKT_FLG_ANONYMOUS);
    /*
     * Set authtime to be the same as header or evidence ticket's
     */
    enc_tkt_reply.times.authtime = authtime;

    /*
     * Propagate the preauthentication flags through to the returned ticket.
     */
    if (isflagset(header_enc_tkt->flags, TKT_FLG_PRE_AUTH))
        setflag(enc_tkt_reply.flags, TKT_FLG_PRE_AUTH);

    if (isflagset(header_enc_tkt->flags, TKT_FLG_HW_AUTH))
        setflag(enc_tkt_reply.flags, TKT_FLG_HW_AUTH);

    /* starttime is optional, and treated as authtime if not present.
       so we can nuke it if it matches */
    if (enc_tkt_reply.times.starttime == enc_tkt_reply.times.authtime)
        enc_tkt_reply.times.starttime = 0;

    if (isflagset(c_flags, KRB5_KDB_FLAG_PROTOCOL_TRANSITION)) {
        errcode = krb5_unparse_name(kdc_context, s4u_x509_user->user_id.user,
                                    &s4u_name);
    } else if (isflagset(c_flags, KRB5_KDB_FLAG_CONSTRAINED_DELEGATION)) {
        errcode = krb5_unparse_name(kdc_context, subject_tkt->client,
                                    &s4u_name);
    } else {
        errcode = 0;
    }
    if (errcode) {
        status = "UNPARSING S4U CLIENT";
        goto cleanup;
    }

    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
        krb5_enc_tkt_part *t2enc = request->second_ticket[st_idx]->enc_part2;
        encrypting_key = *(t2enc->session);
    } else {
        /*
         * Find the server key
         */
        if ((errcode = krb5_dbe_find_enctype(kdc_context, &server,
                                             -1, /* ignore keytype */
                                             -1, /* Ignore salttype */
                                             0,  /* Get highest kvno */
                                             &server_key))) {
            status = "FINDING_SERVER_KEY";
            goto cleanup;
        }

        if ((errcode = krb5_dbe_find_mkey(kdc_context, master_keylist, &server,
                                          &mkey_ptr))) {
            krb5_keylist_node *tmp_mkey_list;
            /* try refreshing master key list */
            /* XXX it would nice if we had the mkvno here for optimization */
            if (krb5_db_fetch_mkey_list(kdc_context, master_princ,
                                        &master_keyblock, 0, &tmp_mkey_list) == 0) {
                krb5_dbe_free_key_list(kdc_context, master_keylist);
                master_keylist = tmp_mkey_list;
                if ((errcode = krb5_dbe_find_mkey(kdc_context, master_keylist,
                                                  &server, &mkey_ptr))) {
                    status = "FINDING_MASTER_KEY";
                    goto cleanup;
                }
            } else {
                status = "FINDING_MASTER_KEY";
                goto cleanup;
            }
        }

        /*
         * Convert server.key into a real key
         * (it may be encrypted in the database)
         */
        if ((errcode = krb5_dbekd_decrypt_key_data(kdc_context,
                                                   mkey_ptr,
                                                   server_key, &encrypting_key,
                                                   NULL))) {
            status = "DECRYPT_SERVER_KEY";
            goto cleanup;
        }
    }

    if (isflagset(c_flags, KRB5_KDB_FLAG_CONSTRAINED_DELEGATION)) {
        /*
         * Don't allow authorization data to be disabled if constrained
         * delegation is requested. We don't want to deny the server
         * the ability to validate that delegation was used.
         */
        clear(server.attributes, KRB5_KDB_NO_AUTH_DATA_REQUIRED);
    }
    if (isflagset(server.attributes, KRB5_KDB_NO_AUTH_DATA_REQUIRED) == 0) {
        /*
         * If we are not doing protocol transition/constrained delegation
         * try to lookup the client principal so plugins can add additional
         * authorization information.
         *
         * Always validate authorization data for constrained delegation
         * because we must validate the KDC signatures.
         */
        if (!isflagset(c_flags, KRB5_KDB_FLAGS_S4U)) {
            /* Generate authorization data so we can include it in ticket */
            setflag(c_flags, KRB5_KDB_FLAG_INCLUDE_PAC);
            /* Map principals from foreign (possibly non-AD) realms */
            setflag(c_flags, KRB5_KDB_FLAG_MAP_PRINCIPALS);

            assert(c_nprincs == 0); /* should not have been looked up already */

            c_nprincs = 1;
            errcode = krb5_db_get_principal_ext(kdc_context,
                                                subject_tkt->client,
                                                c_flags,
                                                &client,
                                                &c_nprincs,
                                                &more);
            /*
             * We can ignore errors because the principal may be a
             * valid cross-realm principal for which we have no local
             * mapping. But we do want to check that at most one entry
             * was returned.
             */
            if (errcode == 0 && (more || c_nprincs > 1)) {
                errcode = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
                goto cleanup;
            } else if (errcode) {
                c_nprincs = 0;
            }
        }
    }

    if (isflagset(c_flags, KRB5_KDB_FLAG_PROTOCOL_TRANSITION) &&
        !isflagset(c_flags, KRB5_KDB_FLAG_CROSS_REALM))
        enc_tkt_reply.client = s4u_x509_user->user_id.user;
    else
        enc_tkt_reply.client = subject_tkt->client;

    enc_tkt_reply.session = &session_key;
    enc_tkt_reply.transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
    enc_tkt_reply.transited.tr_contents = empty_string; /* equivalent of "" */

    errcode = handle_authdata(kdc_context,
                              c_flags,
                              (c_nprincs != 0) ? &client : NULL,
                              &server,
                              (k_nprincs != 0) ? &krbtgt : NULL,
                              subkey != NULL ? subkey :
                              header_ticket->enc_part2->session,
                              &encrypting_key, /* U2U or server key */
                              tgskey,
                              pkt,
                              request,
                              s4u_x509_user ?
                              s4u_x509_user->user_id.user : NULL,
                              subject_tkt,
                              &enc_tkt_reply);
    if (errcode) {
        krb5_klog_syslog(LOG_INFO, "TGS_REQ : handle_authdata (%d)", errcode);
        status = "HANDLE_AUTHDATA";
        goto cleanup;
    }


    /*
     * Only add the realm of the presented tgt to the transited list if
     * it is different than the local realm (cross-realm) and it is different
     * than the realm of the client (since the realm of the client is already
     * implicitly part of the transited list and should not be explicitly
     * listed).
     */
    /* realm compare is like strcmp, but knows how to deal with these args */
    if (realm_compare(header_ticket->server, tgs_server) ||
        realm_compare(header_ticket->server, enc_tkt_reply.client)) {
        /* tgt issued by local realm or issued by realm of client */
        enc_tkt_reply.transited = header_enc_tkt->transited;
    } else {
        /* tgt issued by some other realm and not the realm of the client */
        /* assemble new transited field into allocated storage */
        if (header_enc_tkt->transited.tr_type !=
            KRB5_DOMAIN_X500_COMPRESS) {
            status = "BAD_TRTYPE";
            errcode = KRB5KDC_ERR_TRTYPE_NOSUPP;
            goto cleanup;
        }
        enc_tkt_transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
        enc_tkt_transited.magic = 0;
        enc_tkt_transited.tr_contents.magic = 0;
        enc_tkt_transited.tr_contents.data = 0;
        enc_tkt_transited.tr_contents.length = 0;
        enc_tkt_reply.transited = enc_tkt_transited;
        if ((errcode =
             add_to_transited(&header_enc_tkt->transited.tr_contents,
                              &enc_tkt_reply.transited.tr_contents,
                              header_ticket->server,
                              enc_tkt_reply.client,
                              request->server))) {
            status = "ADD_TR_FAIL";
            goto cleanup;
        }
        newtransited = 1;
    }
    if (isflagset(c_flags, KRB5_KDB_FLAG_CROSS_REALM)) {
        errcode = validate_transit_path(kdc_context, header_enc_tkt->client,
                                        &server,
                                        (k_nprincs != 0) ? &krbtgt : NULL);
        if (errcode) {
            status = "NON_TRANSITIVE";
            goto cleanup;
        }
    }
    if (!isflagset (request->kdc_options, KDC_OPT_DISABLE_TRANSITED_CHECK)) {
        unsigned int tlen;
        char *tdots;

        errcode = kdc_check_transited_list (kdc_context,
                                            &enc_tkt_reply.transited.tr_contents,
                                            krb5_princ_realm (kdc_context, header_enc_tkt->client),
                                            krb5_princ_realm (kdc_context, request->server));
        tlen = enc_tkt_reply.transited.tr_contents.length;
        tdots = tlen > 125 ? "..." : "";
        tlen = tlen > 125 ? 125 : tlen;

        if (errcode == 0) {
            setflag (enc_tkt_reply.flags, TKT_FLG_TRANSIT_POLICY_CHECKED);
        } else if (errcode == KRB5KRB_AP_ERR_ILL_CR_TKT)
            krb5_klog_syslog (LOG_INFO,
                              "bad realm transit path from '%s' to '%s' "
                              "via '%.*s%s'",
                              cname ? cname : "<unknown client>",
                              sname ? sname : "<unknown server>",
                              tlen,
                              enc_tkt_reply.transited.tr_contents.data,
                              tdots);
        else {
            emsg = krb5_get_error_message(kdc_context, errcode);
            krb5_klog_syslog (LOG_ERR,
                              "unexpected error checking transit from "
                              "'%s' to '%s' via '%.*s%s': %s",
                              cname ? cname : "<unknown client>",
                              sname ? sname : "<unknown server>",
                              tlen,
                              enc_tkt_reply.transited.tr_contents.data,
                              tdots, emsg);
            krb5_free_error_message(kdc_context, emsg);
            emsg = NULL;
        }
    } else
        krb5_klog_syslog (LOG_INFO, "not checking transit path");
    if (reject_bad_transit
        && !isflagset (enc_tkt_reply.flags, TKT_FLG_TRANSIT_POLICY_CHECKED)) {
        errcode = KRB5KDC_ERR_POLICY;
        status = "BAD_TRANSIT";
        goto cleanup;
    }

    ticket_reply.enc_part2 = &enc_tkt_reply;

    /*
     * If we are doing user-to-user authentication, then make sure
     * that the client for the second ticket matches the request
     * server, and then encrypt the ticket using the session key of
     * the second ticket.
     */
    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
        /*
         * Make sure the client for the second ticket matches
         * requested server.
         */
        krb5_enc_tkt_part *t2enc = request->second_ticket[st_idx]->enc_part2;
        krb5_principal client2 = t2enc->client;
        if (!krb5_principal_compare(kdc_context, request->server, client2)) {
            if ((errcode = krb5_unparse_name(kdc_context, client2, &altcname)))
                altcname = 0;
            if (altcname != NULL)
                limit_string(altcname);

            errcode = KRB5KDC_ERR_SERVER_NOMATCH;
            status = "2ND_TKT_MISMATCH";
            goto cleanup;
        }

        ticket_kvno = 0;
        ticket_reply.enc_part.enctype = t2enc->session->enctype;
        st_idx++;
    } else {
        ticket_kvno = server_key->key_data_kvno;
    }

    errcode = krb5_encrypt_tkt_part(kdc_context, &encrypting_key,
                                    &ticket_reply);
    if (!isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY))
        krb5_free_keyblock_contents(kdc_context, &encrypting_key);
    if (errcode) {
        status = "TKT_ENCRYPT";
        goto cleanup;
    }
    ticket_reply.enc_part.kvno = ticket_kvno;
    /* Start assembling the response */
    reply.msg_type = KRB5_TGS_REP;
    if (isflagset(c_flags, KRB5_KDB_FLAG_PROTOCOL_TRANSITION) &&
        find_pa_data(request->padata, KRB5_PADATA_S4U_X509_USER) != NULL) {
        errcode = kdc_make_s4u2self_rep(kdc_context,
                                        subkey,
                                        header_ticket->enc_part2->session,
                                        s4u_x509_user,
                                        &reply,
                                        &reply_encpart);
        if (errcode) {
            status = "KDC_RETURN_S4U2SELF_PADATA";
            goto cleanup;
        }
    }

    reply.client = enc_tkt_reply.client;
    reply.enc_part.kvno = 0;/* We are using the session key */
    reply.ticket = &ticket_reply;

    reply_encpart.session = &session_key;
    reply_encpart.nonce = request->nonce;

    /* copy the time fields */
    reply_encpart.times = enc_tkt_reply.times;

    /* starttime is optional, and treated as authtime if not present.
       so we can nuke it if it matches */
    if (enc_tkt_reply.times.starttime == enc_tkt_reply.times.authtime)
        enc_tkt_reply.times.starttime = 0;

    nolrentry.lr_type = KRB5_LRQ_NONE;
    nolrentry.value = 0;
    nolrarray[0] = &nolrentry;
    nolrarray[1] = 0;
    reply_encpart.last_req = nolrarray;        /* not available for TGS reqs */
    reply_encpart.key_exp = 0;/* ditto */
    reply_encpart.flags = enc_tkt_reply.flags;
    reply_encpart.server = ticket_reply.server;

    /* use the session key in the ticket, unless there's a subsession key
       in the AP_REQ */
    reply.enc_part.enctype = subkey ? subkey->enctype :
        header_ticket->enc_part2->session->enctype;
    errcode  = kdc_fast_response_handle_padata(state, request, &reply,
                                               subkey ? subkey->enctype : header_ticket->enc_part2->session->enctype);
    if (errcode !=0 ) {
        status = "Preparing FAST padata";
        goto cleanup;
    }
    errcode =kdc_fast_handle_reply_key(state,
                                       subkey?subkey:header_ticket->enc_part2->session, &reply_key);
    if (errcode) {
        status  = "generating reply key";
        goto cleanup;
    }
    errcode = return_enc_padata(kdc_context, pkt, request,
                                reply_key, &server, &reply_encpart,
                                is_referral &&
                                isflagset(s_flags,
                                          KRB5_KDB_FLAG_CANONICALIZE));
    if (errcode) {
        status = "KDC_RETURN_ENC_PADATA";
        goto cleanup;
    }

    errcode = krb5_encode_kdc_rep(kdc_context, KRB5_TGS_REP, &reply_encpart,
                                  subkey ? 1 : 0,
                                  reply_key,
                                  &reply, response);
    if (errcode) {
        status = "ENCODE_KDC_REP";
    } else {
        status = "ISSUE";
    }

    memset(ticket_reply.enc_part.ciphertext.data, 0,
           ticket_reply.enc_part.ciphertext.length);
    free(ticket_reply.enc_part.ciphertext.data);
    /* these parts are left on as a courtesy from krb5_encode_kdc_rep so we
       can use them in raw form if needed.  But, we don't... */
    memset(reply.enc_part.ciphertext.data, 0,
           reply.enc_part.ciphertext.length);
    free(reply.enc_part.ciphertext.data);

cleanup:
    assert(status != NULL);
    if (reply_key)
        krb5_free_keyblock(kdc_context, reply_key);
    if (errcode)
        emsg = krb5_get_error_message (kdc_context, errcode);
    log_tgs_req(from, request, &reply, cname, sname, altcname, authtime,
                c_flags, s4u_name, status, errcode, emsg);
    if (errcode) {
        krb5_free_error_message (kdc_context, emsg);
        emsg = NULL;
    }

    if (errcode) {
        int got_err = 0;
        if (status == 0) {
            status = krb5_get_error_message (kdc_context, errcode);
            got_err = 1;
        }
        errcode -= ERROR_TABLE_BASE_krb5;
        if (errcode < 0 || errcode > 128)
            errcode = KRB_ERR_GENERIC;

        retval = prepare_error_tgs(state, request, header_ticket, errcode,
                                   nprincs ? server.princ : NULL,
                                   response, status, &e_data);
        if (got_err) {
            krb5_free_error_message (kdc_context, status);
            status = 0;
        }
    }

    if (header_ticket != NULL)
        krb5_free_ticket(kdc_context, header_ticket);
    if (request != NULL)
        krb5_free_kdc_req(kdc_context, request);
    if (state)
        kdc_free_rstate(state);
    if (cname != NULL)
        free(cname);
    if (sname != NULL)
        free(sname);
    if (nprincs != 0)
        krb5_db_free_principal(kdc_context, &server, 1);
    if (session_key.contents != NULL)
        krb5_free_keyblock_contents(kdc_context, &session_key);
    if (newtransited)
        free(enc_tkt_reply.transited.tr_contents.data);
    if (k_nprincs)
        krb5_db_free_principal(kdc_context, &krbtgt, k_nprincs);
    if (c_nprincs)
        krb5_db_free_principal(kdc_context, &client, c_nprincs);
    if (s4u_x509_user != NULL)
        krb5_free_pa_s4u_x509_user(kdc_context, s4u_x509_user);
    if (kdc_issued_auth_data != NULL)
        krb5_free_authdata(kdc_context, kdc_issued_auth_data);
    if (s4u_name != NULL)
        free(s4u_name);
    if (subkey != NULL)
        krb5_free_keyblock(kdc_context, subkey);
    if (tgskey != NULL)
        krb5_free_keyblock(kdc_context, tgskey);
    if (reply.padata)
        krb5_free_pa_data(kdc_context, reply.padata);
    if (reply_encpart.enc_padata)
        krb5_free_pa_data(kdc_context, reply_encpart.enc_padata);
    if (enc_tkt_reply.authorization_data != NULL)
        krb5_free_authdata(kdc_context, enc_tkt_reply.authorization_data);
    krb5_free_data_contents(kdc_context, &e_data);

    return retval;
}

static krb5_error_code
prepare_error_tgs (struct kdc_request_state *state,
                   krb5_kdc_req *request, krb5_ticket *ticket, int error,
                   krb5_principal canon_server,
                   krb5_data **response, const char *status,
                   krb5_data *e_data)
{
    krb5_error errpkt;
    krb5_error_code retval = 0;
    krb5_data *scratch;

    errpkt.ctime = request->nonce;
    errpkt.cusec = 0;

    if ((retval = krb5_us_timeofday(kdc_context, &errpkt.stime,
                                    &errpkt.susec)))
        return(retval);
    errpkt.error = error;
    errpkt.server = request->server;
    if (ticket && ticket->enc_part2)
        errpkt.client = ticket->enc_part2->client;
    else
        errpkt.client = NULL;
    errpkt.text.length = strlen(status) + 1;
    if (!(errpkt.text.data = strdup(status)))
        return ENOMEM;

    if (!(scratch = (krb5_data *)malloc(sizeof(*scratch)))) {
        free(errpkt.text.data);
        return ENOMEM;
    }
    errpkt.e_data = *e_data;
    if (state)
        retval = kdc_fast_handle_error(kdc_context, state, request, NULL, &errpkt);
    if (retval) {
        free(scratch);
        free(errpkt.text.data);
        return retval;
    }
    retval = krb5_mk_error(kdc_context, &errpkt, scratch);
    free(errpkt.text.data);
    if (retval)
        free(scratch);
    else
        *response = scratch;

    return retval;
}

/*
 * The request seems to be for a ticket-granting service somewhere else,
 * but we don't have a ticket for the final TGS.  Try to give the requestor
 * some intermediate realm.
 */
static void
find_alternate_tgs(krb5_kdc_req *request, krb5_db_entry *server,
                   krb5_boolean *more, int *nprincs)
{
    krb5_error_code retval;
    krb5_principal *plist, *pl2;
    krb5_data tmp;

    *nprincs = 0;
    *more = FALSE;

    /*
     * Call to krb5_princ_component is normally not safe but is so
     * here only because find_alternate_tgs() is only called from
     * somewhere that has already checked the number of components in
     * the principal.
     */
    if ((retval = krb5_walk_realm_tree(kdc_context,
                                       krb5_princ_realm(kdc_context, request->server),
                                       krb5_princ_component(kdc_context, request->server, 1),
                                       &plist, KRB5_REALM_BRANCH_CHAR)))
        return;

    /* move to the end */
    for (pl2 = plist; *pl2; pl2++);

    /* the first entry in this array is for krbtgt/local@local, so we
       ignore it */
    while (--pl2 > plist) {
        *nprincs = 1;
        tmp = *krb5_princ_realm(kdc_context, *pl2);
        krb5_princ_set_realm(kdc_context, *pl2,
                             krb5_princ_realm(kdc_context, tgs_server));
        retval = get_principal(kdc_context, *pl2, server, nprincs, more);
        krb5_princ_set_realm(kdc_context, *pl2, &tmp);
        if (retval) {
            *nprincs = 0;
            *more = FALSE;
            krb5_free_realm_tree(kdc_context, plist);
            return;
        }
        if (*more) {
            krb5_db_free_principal(kdc_context, server, *nprincs);
            continue;
        } else if (*nprincs == 1) {
            /* Found it! */
            krb5_principal tmpprinc;

            tmp = *krb5_princ_realm(kdc_context, *pl2);
            krb5_princ_set_realm(kdc_context, *pl2,
                                 krb5_princ_realm(kdc_context, tgs_server));
            if ((retval = krb5_copy_principal(kdc_context, *pl2, &tmpprinc))) {
                krb5_db_free_principal(kdc_context, server, *nprincs);
                krb5_princ_set_realm(kdc_context, *pl2, &tmp);
                continue;
            }
            krb5_princ_set_realm(kdc_context, *pl2, &tmp);

            krb5_free_principal(kdc_context, request->server);
            request->server = tmpprinc;
            log_tgs_alt_tgt(request->server);
            krb5_free_realm_tree(kdc_context, plist);
            return;
        }
        krb5_db_free_principal(kdc_context, server, *nprincs);
        continue;
    }

    *nprincs = 0;
    *more = FALSE;
    krb5_free_realm_tree(kdc_context, plist);
    return;
}

static krb5_int32
prep_reprocess_req(krb5_kdc_req *request, krb5_principal *krbtgt_princ)
{
    krb5_error_code retval = KRB5KRB_AP_ERR_BADMATCH;
    char **realms, **cpp, *temp_buf=NULL;
    krb5_data *comp1 = NULL, *comp2 = NULL;
    char *comp1_str = NULL;

    /* By now we know that server principal name is unknown.
     * If CANONICALIZE flag is set in the request
     * If req is not U2U authn. req
     * the requested server princ. has exactly two components
     * either
     *      the name type is NT-SRV-HST
     *      or name type is NT-UNKNOWN and
     *         the 1st component is listed in conf file under host_based_services
     * the 1st component is not in a list in conf under "no_host_referral"
     * the 2d component looks like fully-qualified domain name (FQDN)
     * If all of these conditions are satisfied - try mapping the FQDN and
     * re-process the request as if client had asked for cross-realm TGT.
     */
    if (isflagset(request->kdc_options, KDC_OPT_CANONICALIZE) &&
        !isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY) &&
        krb5_princ_size(kdc_context, request->server) == 2) {

        comp1 = krb5_princ_component(kdc_context, request->server, 0);
        comp2 = krb5_princ_component(kdc_context, request->server, 1);

        comp1_str = calloc(1,comp1->length+1);
        if (!comp1_str) {
            retval = ENOMEM;
            goto cleanup;
        }
        strlcpy(comp1_str,comp1->data,comp1->length+1);

        if ((krb5_princ_type(kdc_context, request->server) == KRB5_NT_SRV_HST ||
             krb5_princ_type(kdc_context, request->server) == KRB5_NT_SRV_INST ||
             (krb5_princ_type(kdc_context, request->server) == KRB5_NT_UNKNOWN &&
              kdc_active_realm->realm_host_based_services != NULL &&
              (krb5_match_config_pattern(kdc_active_realm->realm_host_based_services,
                                         comp1_str) == TRUE ||
               krb5_match_config_pattern(kdc_active_realm->realm_host_based_services,
                                         KRB5_CONF_ASTERISK) == TRUE))) &&
            (kdc_active_realm->realm_no_host_referral == NULL ||
             (krb5_match_config_pattern(kdc_active_realm->realm_no_host_referral,
                                        KRB5_CONF_ASTERISK) == FALSE &&
              krb5_match_config_pattern(kdc_active_realm->realm_no_host_referral,
                                        comp1_str) == FALSE))) {

            if (memchr(comp2->data, '.', comp2->length) == NULL)
                goto cleanup;
            temp_buf = calloc(1, comp2->length+1);
            if (!temp_buf) {
                retval = ENOMEM;
                goto cleanup;
            }
            strlcpy(temp_buf, comp2->data,comp2->length+1);
            retval = krb5int_get_domain_realm_mapping(kdc_context, temp_buf, &realms);
            free(temp_buf);
            if (retval) {
                /* no match found */
                kdc_err(kdc_context, retval, "unable to find realm of host");
                goto cleanup;
            }
            if (realms == 0) {
                retval = KRB5KRB_AP_ERR_BADMATCH;
                goto cleanup;
            }
            if (realms[0] == 0) {
                free(realms);
                retval = KRB5KRB_AP_ERR_BADMATCH;
                goto cleanup;
            }
            /* Modify request.
             * Construct cross-realm tgt :  krbtgt/REMOTE_REALM@LOCAL_REALM
             * and use it as a principal in this req.
             */
            retval = krb5_build_principal(kdc_context, krbtgt_princ,
                                          (*request->server).realm.length,
                                          (*request->server).realm.data,
                                          "krbtgt", realms[0], (char *)0);
            for (cpp = realms; *cpp; cpp++)
                free(*cpp);
        }
    }
cleanup:
    free(comp1_str);

    return retval;
}
