/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2006 Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Red Hat, Inc., nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
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

/*
 * Checksum the request body with the user's long-term key.
 *
 * The e-data from the KDC is a list of network-byte-order 32-bit integers
 * listing key types which the KDC has for the user.
 *
 * The client uses one of these key types to generate a checksum over the body
 * of the request, and includes the checksum in the AS-REQ as preauthentication
 * data.
 *
 * The AS-REP carries no preauthentication data for this scheme.
 */

#ident "$Id: cksum_body_main.c,v 1.4 2007/01/02 22:33:50 kwc Exp $"

#include "autoconf.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <arpa/inet.h>
#include <stdio.h>

#include <krb5/krb5.h>
#include <krb5/preauth_plugin.h>

/* This is not a standardized value.  It's defined here only to make it easier
 * to change in this module. */
#define KRB5_PADATA_CKSUM_BODY_REQ 130

struct server_stats{
    int successes, failures;
};

typedef struct _test_svr_req_ctx {
    int value1;
    int value2;
} test_svr_req_ctx;

static int
client_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_REAL;
}

static krb5_error_code
client_process(krb5_context kcontext,
               krb5_clpreauth_moddata moddata,
               krb5_clpreauth_modreq modreq,
               krb5_get_init_creds_opt *opt,
               krb5_clpreauth_callbacks cb,
               krb5_clpreauth_rock rock,
               krb5_kdc_req *request,
               krb5_data *encoded_request_body,
               krb5_data *encoded_previous_request,
               krb5_pa_data *pa_data,
               krb5_prompter_fct prompter,
               void *prompter_data,
               krb5_pa_data ***out_pa_data)
{
    krb5_pa_data **send_pa;
    krb5_checksum checksum;
    krb5_cksumtype *cksumtypes;
    krb5_error_code status = 0;
    krb5_int32 cksumtype;
    unsigned int i, cksumtype_count;
    int num_gic_info = 0;
    krb5_gic_opt_pa_data *gic_info;
    krb5_keyblock *as_key;

    status = krb5_get_init_creds_opt_get_pa(kcontext, opt,
                                            &num_gic_info, &gic_info);
    if (status && status != ENOENT) {
#ifdef DEBUG
        fprintf(stderr, "Error from krb5_get_init_creds_opt_get_pa: %s\n",
                error_message(status));
#endif
        return status;
    }
#ifdef DEBUG
    fprintf(stderr, "(cksum_body) Got the following gic options:\n");
#endif
    for (i = 0; i < num_gic_info; i++) {
#ifdef DEBUG
        fprintf(stderr, "  '%s' = '%s'\n", gic_info[i].attr, gic_info[i].value);
#endif
    }
    krb5_get_init_creds_opt_free_pa(kcontext, num_gic_info, gic_info);

    memset(&checksum, 0, sizeof(checksum));

    status = cb->get_as_key(kcontext, rock, &as_key);
    if (status != 0)
        return status;
#ifdef DEBUG
    fprintf(stderr, "Got AS key (type = %d).\n", as_key->enctype);
#endif

    /* Determine an appropriate checksum type for this key. */
    cksumtype_count = 0;
    cksumtypes = NULL;
    status = krb5_c_keyed_checksum_types(kcontext, as_key->enctype,
                                         &cksumtype_count, &cksumtypes);
    if (status != 0)
        return status;

    /* Generate the checksum. */
    for (i = 0; i < cksumtype_count; i++) {
        status = krb5_c_make_checksum(kcontext, cksumtypes[i], as_key,
                                      KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
                                      encoded_request_body,
                                      &checksum);
        if (status == 0) {
#ifdef DEBUG
            fprintf(stderr, "Made checksum (type = %d, %d bytes).\n",
                    checksum.checksum_type, encoded_request_body->length);
#endif
            break;
        }
    }
    cksumtype = htonl(cksumtypes[i]);
    krb5_free_cksumtypes(kcontext, cksumtypes);
    if (status != 0) {
        if (checksum.length > 0)
            krb5_free_checksum_contents(kcontext, &checksum);
        return status;
    }

    /* Allocate the preauth data structure. */
    send_pa = malloc(2 * sizeof(krb5_pa_data *));
    if (send_pa == NULL) {
        krb5_free_checksum_contents(kcontext, &checksum);
        return ENOMEM;
    }
    send_pa[1] = NULL;  /* Terminate list */
    send_pa[0] = malloc(sizeof(krb5_pa_data));
    if (send_pa[0] == NULL) {
        krb5_free_checksum_contents(kcontext, &checksum);
        free(send_pa);
        return ENOMEM;
    }
    send_pa[0]->pa_type = KRB5_PADATA_CKSUM_BODY_REQ;
    send_pa[0]->length = 4 + checksum.length;
    send_pa[0]->contents = malloc(4 + checksum.length);
    if (send_pa[0]->contents == NULL) {
        krb5_free_checksum_contents(kcontext, &checksum);
        free(send_pa[0]);
        free(send_pa);
        return ENOMEM;
    }

    /* Store the checksum. */
    memcpy(send_pa[0]->contents, &cksumtype, 4);
    memcpy(send_pa[0]->contents + 4, checksum.contents, checksum.length);
    *out_pa_data = send_pa;

    /* Clean up. */
    krb5_free_checksum_contents(kcontext, &checksum);

    return 0;
}

static krb5_error_code
client_gic_opt(krb5_context kcontext,
               krb5_clpreauth_moddata moddata,
               krb5_get_init_creds_opt *opt,
               const char *attr,
               const char *value)
{
#ifdef DEBUG
    fprintf(stderr, "(cksum_body) client_gic_opt: received '%s' = '%s'\n",
            attr, value);
#endif
    return 0;
}

/* Initialize and tear down the server-side module, and do stat tracking. */
static krb5_error_code
server_init(krb5_context kcontext, krb5_kdcpreauth_moddata *moddata_out,
            const char **realmnames)
{
    struct server_stats *stats;
    stats = malloc(sizeof(struct server_stats));
    if (stats == NULL)
        return ENOMEM;
    stats->successes = 0;
    stats->failures = 0;
    *moddata_out = (krb5_kdcpreauth_moddata)stats;
    return 0;
}
static void
server_fini(krb5_context kcontext, krb5_kdcpreauth_moddata moddata)
{
    struct server_stats *stats;
    stats = (struct server_stats *)moddata;
    if (stats != NULL) {
#ifdef DEBUG
        fprintf(stderr, "Total: %d clients failed, %d succeeded.\n",
                stats->failures, stats->successes);
#endif
        free(stats);
    }
}

/* Obtain and return any preauthentication data (which is destined for the
 * client) which matches type data->pa_type. */
static void
server_get_edata(krb5_context kcontext, krb5_kdc_req *request,
                 krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
                 krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
                 krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{
    krb5_keyblock *keys;
    krb5_int32 *enctypes, enctype;
    krb5_pa_data *data;
    int i;

    /* Retrieve the client's keys. */
    if (cb->client_keys(kcontext, rock, &keys) != 0) {
#ifdef DEBUG
        fprintf(stderr, "Error retrieving client keys.\n");
#endif
        (*respond)(arg, KRB5KDC_ERR_PADATA_TYPE_NOSUPP, NULL);
        return;
    }

    /* Count which types of keys we've got. */
    for (i = 0; keys[i].enctype != 0; i++);

    /* Return the list of encryption types. */
    enctypes = malloc((unsigned)i * 4);
    if (enctypes == NULL) {
        cb->free_keys(kcontext, rock, keys);
        (*respond)(arg, ENOMEM, NULL);
        return;
    }
#ifdef DEBUG
    fprintf(stderr, "Supported enctypes = {");
#endif
    for (i = 0; keys[i].enctype != 0; i++) {
#ifdef DEBUG
        fprintf(stderr, "%s%d", (i > 0) ? ", " : "", keys[i].enctype);
#endif
        enctype = htonl(keys[i].enctype);
        memcpy(&enctypes[i], &enctype, 4);
    }
#ifdef DEBUG
    fprintf(stderr, "}.\n");
#endif
    cb->free_keys(kcontext, rock, keys);
    data = malloc(sizeof(*data));
    if (data == NULL) {
        free(enctypes);
        (*respond)(arg, ENOMEM, NULL);
    }
    data->magic = KV5M_PA_DATA;
    data->pa_type = KRB5_PADATA_CKSUM_BODY_REQ;
    data->length = (i * 4);
    data->contents = (unsigned char *) enctypes;
    (*respond)(arg, 0, data);
}

/* Verify a request from a client. */
static void
server_verify(krb5_context kcontext,
              krb5_data *req_pkt,
              krb5_kdc_req *request,
              krb5_enc_tkt_part *enc_tkt_reply,
              krb5_pa_data *data,
              krb5_kdcpreauth_callbacks cb,
              krb5_kdcpreauth_rock rock,
              krb5_kdcpreauth_moddata moddata,
              krb5_kdcpreauth_verify_respond_fn respond,
              void *arg)
{
    krb5_int32 cksumtype;
    krb5_checksum checksum;
    krb5_boolean valid;
    krb5_data *req_body;
    krb5_keyblock *keys, *key;
    size_t length;
    unsigned int i, cksumtypes_count;
    krb5_cksumtype *cksumtypes;
    krb5_error_code status;
    struct server_stats *stats;
    test_svr_req_ctx *svr_req_ctx;
    krb5_authdata **my_authz_data = NULL;

    stats = (struct server_stats *)moddata;

#ifdef DEBUG
    fprintf(stderr, "cksum_body: server_verify\n");
#endif
    /* Verify the preauth data.  Start with the checksum type. */
    if (data->length < 4) {
        stats->failures++;
        (*respond)(arg, KRB5KDC_ERR_PREAUTH_FAILED, NULL, NULL, NULL);
        return;
    }
    memcpy(&cksumtype, data->contents, 4);
    memset(&checksum, 0, sizeof(checksum));
    checksum.checksum_type = ntohl(cksumtype);

    /* Verify that the amount of data we have left is what we expect. */
    if (krb5_c_checksum_length(kcontext, checksum.checksum_type,
                               &length) != 0) {
#ifdef DEBUG
        fprintf(stderr, "Error determining checksum size (type = %d). "
                "Is it supported?\n", checksum.checksum_type);
#endif
        stats->failures++;
        (*respond)(arg, KRB5KDC_ERR_SUMTYPE_NOSUPP, NULL, NULL, NULL);
        return;
    }
    if (data->length - 4 != length) {
#ifdef DEBUG
        fprintf(stderr, "Checksum size doesn't match client packet size.\n");
#endif
        stats->failures++;
        (*respond)(arg, KRB5KDC_ERR_PREAUTH_FAILED, NULL, NULL, NULL);
        return;
    }
    checksum.length = length;

    /* Pull up the client's keys. */
    if (cb->client_keys(kcontext, rock, &keys) != 0) {
#ifdef DEBUG
        fprintf(stderr, "Error retrieving client keys.\n");
#endif
        stats->failures++;
        (*respond)(arg, KRB5KDC_ERR_PREAUTH_FAILED, NULL, NULL, NULL);
        return;
    }

    /* Find the key which would have been used to generate the checksum. */
    for (key = keys; key->enctype != 0; key++) {
        cksumtypes_count = 0;
        cksumtypes = NULL;
        if (krb5_c_keyed_checksum_types(kcontext, key->enctype,
                                        &cksumtypes_count, &cksumtypes) != 0)
            continue;
        for (i = 0; i < cksumtypes_count; i++) {
            if (cksumtypes[i] == checksum.checksum_type)
                break;
        }
        if (cksumtypes != NULL)
            krb5_free_cksumtypes(kcontext, cksumtypes);
        if (i < cksumtypes_count) {
#ifdef DEBUG
            fprintf(stderr, "Found checksum key.\n");
#endif
            break;
        }
    }
    if (key->enctype == 0) {
        cb->free_keys(kcontext, rock, keys);
        stats->failures++;
        (*respond)(arg, KRB5KDC_ERR_SUMTYPE_NOSUPP, NULL, NULL, NULL);
        return;
    }

    /* Save a copy of the key. */
    if (krb5_copy_keyblock(kcontext, keys, &key) != 0) {
        cb->free_keys(kcontext, rock, keys);
        stats->failures++;
        (*respond)(arg, KRB5KDC_ERR_SUMTYPE_NOSUPP, NULL, NULL, NULL);
        return;
    }
    cb->free_keys(kcontext, rock, keys);

    req_body = cb->request_body(kcontext, rock);

#ifdef DEBUG
    fprintf(stderr, "AS key type %d, checksum type %d, %d bytes.\n",
            key->enctype, checksum.checksum_type, req_body->length);
#endif

    /* Verify the checksum itself. */
    checksum.contents = data->contents + 4;
    valid = FALSE;
    status = krb5_c_verify_checksum(kcontext, key,
                                    KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
                                    req_body, &checksum, &valid);

    /* Clean up. */
    krb5_free_keyblock(kcontext, key);

    /* Evaluate our results. */
    if ((status != 0) || (!valid)) {
#ifdef DEBUG
        if (status != 0) {
            fprintf(stderr, "Error in checksum verification.\n");
        } else {
            fprintf(stderr, "Checksum mismatch.\n");
        }
#endif
        stats->failures++;
        (*respond)(arg, KRB5KDC_ERR_PREAUTH_FAILED, NULL, NULL, NULL);
        return;
    }

    /*
     * Return some junk authorization data just to exercise the
     * code path handling the returned authorization data.
     *
     * NOTE that this is NOT VALID authorization data!
     */
#ifdef DEBUG
    fprintf(stderr, "cksum_body: doing authorization data!\n");
#endif
    my_authz_data = malloc(2 * sizeof(*my_authz_data));
    if (my_authz_data != NULL) {
#if 1 /* USE_5000_AD */
#define AD_ALLOC_SIZE 5000
        /* ad_header consists of a sequence tag (0x30) and length
         * (0x82 0x1384) followed by octet string tag (0x04) and
         * length (0x82 0x1380) */
        krb5_octet ad_header[] = {0x30, 0x82, 0x13, 0x84, 0x04, 0x82, 0x13, 0x80};
#else
#define AD_ALLOC_SIZE 100
        /* ad_header consists of a sequence tag (0x30) and length
         * (0x62) followed by octet string tag (0x04) and length
         * (0x60) */
        krb5_octet ad_header[] = {0x30, 0x62, 0x04, 0x60};
#endif

        my_authz_data[1] = NULL;
        my_authz_data[0] = malloc(sizeof(krb5_authdata));
        if (my_authz_data[0] == NULL) {
            free(my_authz_data);
            (*respond)(arg, ENOMEM, NULL, NULL, NULL);
            return;
        }
        my_authz_data[0]->contents = malloc(AD_ALLOC_SIZE);
        if (my_authz_data[0]->contents == NULL) {
            free(my_authz_data[0]);
            free(my_authz_data);
            (*respond)(arg, ENOMEM, NULL, NULL, NULL);
            return;
        }
        memset(my_authz_data[0]->contents, '\0', AD_ALLOC_SIZE);
        my_authz_data[0]->magic = KV5M_AUTHDATA;
        my_authz_data[0]->ad_type = 1;
        my_authz_data[0]->length = AD_ALLOC_SIZE;
        memcpy(my_authz_data[0]->contents, ad_header, sizeof(ad_header));
        snprintf(my_authz_data[0]->contents + sizeof(ad_header),
                 AD_ALLOC_SIZE - sizeof(ad_header),
                 "cksum authorization data: %d bytes worth!\n", AD_ALLOC_SIZE);
#ifdef DEBUG
        fprintf(stderr, "Returning %d bytes of authorization data\n",
                AD_ALLOC_SIZE);
#endif
    }

    /* Return a request context to exercise code that handles it */
    svr_req_ctx = malloc(sizeof(*svr_req_ctx));
    if (svr_req_ctx != NULL) {
        svr_req_ctx->value1 = 111111;
        svr_req_ctx->value2 = 222222;
#ifdef DEBUG
        fprintf(stderr, "server_verify: returning context at %p\n",
                svr_req_ctx);
#endif
    }

    /* Note that preauthentication succeeded. */
    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
    stats->successes++;
    (*respond)(arg, 0, (krb5_kdcpreauth_modreq)svr_req_ctx, NULL, my_authz_data);
}

/* Create the response for a client. */
static krb5_error_code
server_return(krb5_context kcontext,
              krb5_pa_data *padata,
              krb5_data *req_pkt,
              krb5_kdc_req *request,
              krb5_kdc_rep *reply,
              krb5_keyblock *encrypting_key,
              krb5_pa_data **send_pa,
              krb5_kdcpreauth_callbacks cb,
              krb5_kdcpreauth_rock rock,
              krb5_kdcpreauth_moddata moddata,
              krb5_kdcpreauth_modreq modreq)
{
    /* We don't need to send data back on the return trip. */
    *send_pa = NULL;
    return 0;
}

/* Test server request context freeing */
static void
server_free_modreq(krb5_context kcontext,
                   krb5_kdcpreauth_moddata moddata,
                   krb5_kdcpreauth_modreq modreq)
{
    test_svr_req_ctx *svr_req_ctx;
#ifdef DEBUG
    fprintf(stderr, "server_free_modreq: entered!\n");
#endif
    if (modreq == NULL)
        return;

    svr_req_ctx = (test_svr_req_ctx *)modreq;
    if (svr_req_ctx == NULL)
        return;

    if (svr_req_ctx->value1 != 111111 || svr_req_ctx->value2 != 222222) {
        fprintf(stderr, "server_free_modreq: got invalid req context "
                "at %p with values %d and %d\n",
                svr_req_ctx, svr_req_ctx->value1, svr_req_ctx->value2);
        return;
    }
#ifdef DEBUG
    fprintf(stderr, "server_free_modreq: freeing context at %p\n", svr_req_ctx);
#endif
    free(svr_req_ctx);
}

static int
server_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_SUFFICIENT;
}

static krb5_preauthtype supported_client_pa_types[] = {
    KRB5_PADATA_CKSUM_BODY_REQ, 0,
};
static krb5_preauthtype supported_server_pa_types[] = {
    KRB5_PADATA_CKSUM_BODY_REQ, 0,
};

krb5_error_code
clpreauth_cksum_body_initvt(krb5_context context, int maj_ver,
                            int min_ver, krb5_plugin_vtable vtable);
krb5_error_code
kdcpreauth_cksum_body_initvt(krb5_context context, int maj_ver,
                             int min_ver, krb5_plugin_vtable vtable);

krb5_error_code
clpreauth_cksum_body_initvt(krb5_context context, int maj_ver,
                            int min_ver, krb5_plugin_vtable vtable)
{
    krb5_clpreauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_clpreauth_vtable)vtable;
    vt->name = "cksum_body";
    vt->pa_type_list = supported_client_pa_types;
    vt->flags = client_get_flags;
    vt->process = client_process;
    vt->gic_opts = client_gic_opt;
    return 0;
}

krb5_error_code
kdcpreauth_cksum_body_initvt(krb5_context context, int maj_ver,
                             int min_ver, krb5_plugin_vtable vtable)
{
    krb5_kdcpreauth_vtable vt;

    if (maj_ver != -1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_kdcpreauth_vtable)vtable;
    vt->name = "cksum_body";
    vt->pa_type_list = supported_server_pa_types;
    vt->init = server_init;
    vt->fini = server_fini;
    vt->flags = server_get_flags;
    vt->edata = server_get_edata;
    vt->verify = server_verify;
    vt->return_padata = server_return;
    vt->free_modreq = server_free_modreq;
    return 0;
}
