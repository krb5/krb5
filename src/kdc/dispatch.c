/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/dispatch.c - Dispatch an incoming packet */
/*
 * Copyright 1990, 2009 by the Massachusetts Institute of Technology.
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
#include <syslog.h>
#include "kdc_util.h"
#include "extern.h"
#include "adm_proto.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

static krb5_int32 last_usec = 0, last_os_random = 0;

static krb5_error_code make_too_big_error (krb5_data **out);

struct dispatch_state {
    loop_respond_fn respond;
    void *arg;
    krb5_data *request;
    int is_tcp;
};

static void
finish_dispatch(struct dispatch_state *state, krb5_error_code code,
                krb5_data *response)
{
    loop_respond_fn oldrespond = state->respond;
    void *oldarg = state->arg;

    if (state->is_tcp == 0 && response &&
        response->length > max_dgram_reply_size) {
        krb5_free_data(kdc_context, response);
        response = NULL;
        code = make_too_big_error(&response);
        if (code)
            krb5_klog_syslog(LOG_ERR, "error constructing "
                             "KRB_ERR_RESPONSE_TOO_BIG error: %s",
                             error_message(code));
    }

    free(state);
    (*oldrespond)(oldarg, code, response);
}

static void
finish_dispatch_cache(void *arg, krb5_error_code code, krb5_data *response)
{
    struct dispatch_state *state = arg;

#ifndef NOCACHE
    /* Remove the null cache entry unless we actually want to discard this
     * request. */
    if (code != KRB5KDC_ERR_DISCARD)
        kdc_remove_lookaside(kdc_context, state->request);

    /* Put the response into the lookaside buffer (if we produced one). */
    if (code == 0 && response != NULL)
        kdc_insert_lookaside(state->request, response);
#endif

    finish_dispatch(state, code, response);
}

void
dispatch(void *cb, struct sockaddr *local_saddr,
         const krb5_fulladdr *from, krb5_data *pkt, int is_tcp,
         verto_ctx *vctx, loop_respond_fn respond, void *arg)
{
    krb5_error_code retval;
    krb5_kdc_req *as_req;
    krb5_int32 now, now_usec;
    krb5_data *response = NULL;
    struct dispatch_state *state;

    state = malloc(sizeof(*state));
    if (!state) {
        (*respond)(arg, ENOMEM, NULL);
        return;
    }
    state->respond = respond;
    state->arg = arg;
    state->request = pkt;
    state->is_tcp = is_tcp;

    /* decode incoming packet, and dispatch */

#ifndef NOCACHE
    /* try the replay lookaside buffer */
    if (kdc_check_lookaside(pkt, &response)) {
        /* a hit! */
        const char *name = 0;
        char buf[46];

        if (!response || is_tcp != 0 ||
            response->length <= max_dgram_reply_size) {
            name = inet_ntop (ADDRTYPE2FAMILY (from->address->addrtype),
                              from->address->contents, buf, sizeof (buf));
            if (name == 0)
                name = "[unknown address type]";
            if (response)
                krb5_klog_syslog(LOG_INFO,
                                 "DISPATCH: repeated (retransmitted?) request "
                                 "from %s, resending previous response", name);
            else
                krb5_klog_syslog(LOG_INFO,
                                 "DISPATCH: repeated (retransmitted?) request "
                                 "from %s during request processing, dropping "
                                 "repeated request", name);
        }

        finish_dispatch(state, response ? 0 : KRB5KDC_ERR_DISCARD, response);
        return;
    }

    /* Insert a NULL entry into the lookaside to indicate that this request
     * is currently being processed. */
    kdc_insert_lookaside(pkt, NULL);
#endif

    retval = krb5_crypto_us_timeofday(&now, &now_usec);
    if (retval == 0) {
        krb5_int32 usec_difference = now_usec-last_usec;
        krb5_data data;
        if(last_os_random == 0)
            last_os_random = now;
        /* Grab random data from OS every hour*/
        if(now-last_os_random >= 60*60) {
            krb5_c_random_os_entropy(kdc_context, 0, NULL);
            last_os_random = now;
        }

        data.length = sizeof(krb5_int32);
        data.data = (void *) &usec_difference;

        krb5_c_random_add_entropy(kdc_context,
                                  KRB5_C_RANDSOURCE_TIMING, &data);
        last_usec = now_usec;
    }
    /* try TGS_REQ first; they are more common! */

    if (krb5_is_tgs_req(pkt)) {
        retval = process_tgs_req(pkt, from, &response);
    } else if (krb5_is_as_req(pkt)) {
        if (!(retval = decode_krb5_as_req(pkt, &as_req))) {
            /*
             * setup_server_realm() sets up the global realm-specific data
             * pointer.
             * process_as_req frees the request if it is called
             */
            if (!(retval = setup_server_realm(as_req->server))) {
                process_as_req(as_req, pkt, from, vctx, finish_dispatch_cache,
                               state);
                return;
            }
            else
                krb5_free_kdc_req(kdc_context, as_req);
        }
    } else
        retval = KRB5KRB_AP_ERR_MSG_TYPE;

    finish_dispatch(state, retval, response);
}

static krb5_error_code
make_too_big_error (krb5_data **out)
{
    krb5_error errpkt;
    krb5_error_code retval;
    krb5_data *scratch;

    *out = NULL;
    memset(&errpkt, 0, sizeof(errpkt));

    retval = krb5_us_timeofday(kdc_context, &errpkt.stime, &errpkt.susec);
    if (retval)
        return retval;
    errpkt.error = KRB_ERR_RESPONSE_TOO_BIG;
    errpkt.server = tgs_server;
    errpkt.client = NULL;
    errpkt.text.length = 0;
    errpkt.text.data = 0;
    errpkt.e_data.length = 0;
    errpkt.e_data.data = 0;
    scratch = malloc(sizeof(*scratch));
    if (scratch == NULL)
        return ENOMEM;
    retval = krb5_mk_error(kdc_context, &errpkt, scratch);
    if (retval) {
        free(scratch);
        return retval;
    }

    *out = scratch;
    return 0;
}
