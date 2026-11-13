/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/fuzzing/fuzz_gss_exchange.c - fuzzing harness for the GSS initiator
 * and acceptor exchange (init_sec_context/accept_sec_context, wrap/unwrap,
 * mic, context serialisation), with krb5 / SPNEGO / IAKERB mechanisms.
 */
/*
 * Copyright (C) 2026 by the krb5 fuzzer authors.
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
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
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
 * Threat model: GSS tokens are exchanged with unauthenticated peers.  The
 * acceptor parses initiator tokens that fully control the byte stream
 * (SPNEGO/IAKERB/krb5 framing, AP-REQ contents), and the initiator parses
 * acceptor replies which in many deployments are attacker-influenceable.
 * This harness exercises both directions against real credentials.
 *
 * The harness reuses the loopback fake-KDC seam: a generated profile pins
 * the realm's KDC to 127.0.0.1, and a server thread answers AS-REQs and
 * TGS-REQs with library-composed valid replies.  Unlike fuzz_kdc_client,
 * the issued tickets here are real (EncTicketPart encrypted in the long-term
 * key of the issuing service) so that an acceptor with a synthesized keytab
 * can decrypt them, and TGS replies decrypt under the TGT session key or the
 * authenticator subkey, per RFC 4120 key usages.
 *
 * Per iteration the harness:
 *   1. performs a client AS exchange (password flow) and stores the TGT in a
 *      MEMORY ccache;
 *   2. optionally feeds attacker bytes to gss_accept_sec_context with the
 *      real acceptor credential;
 *   3. runs an initiator/acceptor context establishment loop with the
 *      selected mechanism (krb5 or SPNEGO; the IAKERB mechanism was probed
 *      and is excluded from this harness: its in-process credential and
 *      context lifecycle interacts badly with the multi-threaded fake-KDC
 *      seam and the mechglue has no default-acceptor-credential path for
 *      it, see the pair report), feeding each side's output token to the
 *      other;
 *   4. once established, applies wrap/unwrap (both directions), MIC
 *      get/verify, and export/import of the context.
 *
 * Input layout (minimum 4 bytes):
 *   byte 0: mechanism: bit 0 clear selects krb5, set selects SPNEGO
 *   byte 1: initiator flags bits: mutual, replay, sequence, conf, integ
 *   byte 2: enctype selector for all long-term keys
 *   byte 3: post-establishment op bits: wrap/unwrap, mic, export/import,
 *           and bit 3 (0x08): feed bytes 4.. to the acceptor as a raw
 *           initial token before the loop
 *   bytes 4+: raw token payload / wrapped-message plaintext
 */

#include "autoconf.h"
#include <k5-int.h>
#include <gssapi.h>
#include <gssapi/gssapi_ext.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define kMinInputLength 4
#define kMaxInputLength 100000

#define FUZZ_REALM      "FZ"
#define FUZZ_PASSWORD   "GssFuzzUser1!"
#define FUZZ_SVC        "host@" FUZZ_REALM

/* The three mechanism OIDs are exported by the linked GSS library. */
extern const gss_OID gss_mech_krb5;
extern const gss_OID gss_mech_spnego;
extern const gss_OID gss_mech_spnego;

/* Supported enctypes for the long-term keys (all in the default client
 * enctype list). */
static const krb5_enctype etype_table[] = {
    ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
    ENCTYPE_AES256_CTS_HMAC_SHA384_192, ENCTYPE_AES128_CTS_HMAC_SHA256_128
};
#define ETYPE_TABLE_LEN (sizeof(etype_table) / sizeof(etype_table[0]))

/* Protocol error code used for the generic terminating reply. */
#define FALLBACK_ERRCODE KDC_ERR_S_PRINCIPAL_UNKNOWN

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

/* Harness state initialised once. */
static krb5_context g_ctx = NULL;
static krb5_principal g_princ = NULL;      /* user@FZ */
static krb5_principal g_svcprinc = NULL;   /* host@FZ (ticket server) */
static krb5_get_init_creds_opt *g_opt = NULL;
static krb5_keyblock g_tgtkey;             /* long-term key of krbtgt/FZ */
static krb5_keyblock g_svckey;             /* long-term key of host@FZ */
static int g_udp_fd = -1;
static int g_tcp_fd = -1;
static int g_ready = 0;
static gss_cred_id_t g_init_cred = GSS_C_NO_CREDENTIAL;
static gss_cred_id_t g_acct_cred = GSS_C_NO_CREDENTIAL;
static gss_name_t g_target = GSS_C_NO_NAME;

/* Deterministic session-key material handed out inside tickets.  The fake
 * KDC is stateless: the TGS exchange recovers S1 by decrypting the TGT
 * ticket with g_tgtkey, so no cross-request state is needed. */
static krb5_keyblock g_s1key;
static krb5_keyblock g_s2key;

/* The fuzz-controlled selectors, replaced on each iteration. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct reply_script {
    int enctype_idx;
    int served;
} g_script;

/* Write a krb5 keytab (version 2, big-endian fields) with one entry for
 * g_svcprinc using g_svckey, so the acceptor can decrypt issued tickets. */
static int
write_keytab(const char *path, krb5_enctype etype)
{
    FILE *f;
    krb5_int32 len32, zero = 0;
    krb5_int16 ncomp = htons(1), rlen, clen, enctype16, klen;
    krb5_int32 nametype = htonl(KRB5_NT_UNKNOWN);
    krb5_int32 timestamp = htonl((krb5_int32)time(NULL));
    const char *realm = FUZZ_REALM;
    const char *comp = "host";
    unsigned char vno = 1;
    int rlen_n = strlen(realm), clen_n = strlen(comp);
    int body, klen_n = g_svckey.length;

    rlen = htons((krb5_int16)rlen_n);
    clen = htons((krb5_int16)clen_n);
    enctype16 = htons((krb5_int16)etype);
    klen = htons((krb5_int16)klen_n);

    body = sizeof(ncomp) + sizeof(rlen) + rlen_n + sizeof(clen) + clen_n +
        sizeof(nametype) + sizeof(timestamp) + sizeof(vno) +
        sizeof(enctype16) + sizeof(klen) + klen_n;
    len32 = htonl(body);

    f = fopen(path, "wb");
    if (f == NULL)
        return -1;
    if (fputc(0x05, f) == EOF || fputc(0x02, f) == EOF ||
        fwrite(&len32, sizeof(len32), 1, f) != 1 ||
        fwrite(&ncomp, sizeof(ncomp), 1, f) != 1 ||
        fwrite(&rlen, sizeof(rlen), 1, f) != 1 ||
        fwrite(realm, 1, rlen_n, f) != (size_t)rlen_n ||
        fwrite(&clen, sizeof(clen), 1, f) != 1 ||
        fwrite(comp, 1, clen_n, f) != (size_t)clen_n ||
        fwrite(&nametype, sizeof(nametype), 1, f) != 1 ||
        fwrite(&timestamp, sizeof(timestamp), 1, f) != 1 ||
        fputc(vno, f) == EOF ||
        fwrite(&enctype16, sizeof(enctype16), 1, f) != 1 ||
        fwrite(&klen, sizeof(klen), 1, f) != 1 ||
        fwrite(g_svckey.contents, 1, klen_n, f) != (size_t)klen_n ||
        fwrite(&zero, sizeof(zero), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* Compose a KRB-ERROR reply (both principal fields mandatory in the
 * encoder; the fallback code terminates the client's exchange). */
static uint8_t *
compose_error(krb5_ui_4 code, size_t *len_out)
{
    krb5_error e;
    krb5_data *der = NULL;
    uint8_t *buf;

    memset(&e, 0, sizeof(e));
    e.ctime = time(NULL);
    e.cusec = 0;
    e.susec = 0;
    e.stime = time(NULL);
    e.error = code;
    e.client = g_princ;
    e.server = g_svcprinc;
    e.text = empty_data();
    e.e_data = empty_data();

    if (encode_krb5_error(&e, &der) != 0)
        return NULL;
    buf = malloc(der->length);
    if (buf != NULL) {
        memcpy(buf, der->data, der->length);
        *len_out = der->length;
    }
    krb5_free_data(g_ctx, der);
    return buf;
}

/* Build a real ticket for `server' encrypted in `key' (usage
 * KDC_REP_TICKET), carrying `session', `client', flags and lifetime bounded

 * by endtime.  The encrypted ticket enc-part is carried inside the ticket
 * structure itself (the caller frees it with the ticket). */
static krb5_error_code
build_ticket(const krb5_keyblock *key, const krb5_keyblock *session,
             krb5_const_principal client, krb5_const_principal server,
             krb5_timestamp endtime, krb5_flags flags, krb5_ticket *ticket)
{
    krb5_error_code ret;
    krb5_enc_tkt_part etkt;
    krb5_data *der = NULL;
    size_t bodylen;
    time_t now = time(NULL);

    memset(&etkt, 0, sizeof(etkt));
    etkt.flags = flags;
    etkt.session = (krb5_keyblock *)session;
    etkt.client = (krb5_principal)client;
    etkt.transited.tr_type = 0;
    etkt.transited.tr_contents = empty_data();
    etkt.times.authtime = now;
    etkt.times.starttime = now;
    etkt.times.endtime = endtime;
    etkt.times.renew_till = endtime;
    etkt.caddrs = NULL;
    etkt.authorization_data = NULL;

    ticket->server = (krb5_principal)server;
    ticket->enc_part.magic = 0;
    ticket->enc_part.enctype = key->enctype;
    ticket->enc_part.kvno = 1;

    ret = encode_krb5_enc_tkt_part(&etkt, &der);
    if (ret)
        goto cleanup;
    ret = krb5_c_encrypt_length(g_ctx, key->enctype, der->length,
                                &bodylen);
    if (ret)
        goto cleanup;
    ticket->enc_part.ciphertext.data = malloc(bodylen);
    if (ticket->enc_part.ciphertext.data == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    ticket->enc_part.ciphertext.length = bodylen;
    ret = krb5_c_encrypt(g_ctx, key, KRB5_KEYUSAGE_KDC_REP_TICKET, NULL,
                         der, &ticket->enc_part);
    if (ret) {
        free(ticket->enc_part.ciphertext.data);
        ticket->enc_part.ciphertext.data = NULL;
    }

cleanup:
    if (der != NULL)
        krb5_free_data(g_ctx, der);
    return ret;
}

/* Compose a valid AS-REP answering the decoded AS request: the ticket is
 * real (EncTicketPart encrypted in the krbtgt long-term key) so the later
 * TGS exchange can be answered, and the reply is encrypted in the client's
 * password-derived key exactly as the client will derive it. */
static uint8_t *
compose_asrep(const krb5_data *reqder, size_t *len_out)
{
    krb5_error_code ret;
    krb5_kdc_req *req = NULL;
    krb5_kdc_rep rep;
    krb5_ticket ticket;
    krb5_enc_kdc_rep_part ekr;
    krb5_keyblock pkey;
    krb5_data salt, *der = NULL, *out_der = NULL;
    krb5_enc_data enc;
    krb5_enctype etype;
    krb5_data pw = make_data((char *)FUZZ_PASSWORD, strlen(FUZZ_PASSWORD));
    size_t bodylen;
    krb5_last_req_entry lre, *last_req[2];
    uint8_t *buf = NULL;
    time_t now = time(NULL);

    memset(&pkey, 0, sizeof(pkey));
    memset(&enc, 0, sizeof(enc));
    memset(&ticket, 0, sizeof(ticket));
    salt = empty_data();

    if (decode_krb5_as_req(reqder, &req) != 0)
        return NULL;

    etype = etype_table[g_script.enctype_idx % ETYPE_TABLE_LEN];

    ret = krb5_principal2salt(g_ctx, req->client, &salt);
    if (ret)
        goto cleanup;
    ret = krb5_c_string_to_key(g_ctx, etype, &pw, &salt, &pkey);
    if (ret)
        goto cleanup;

    ret = build_ticket(&g_tgtkey, &g_s1key, req->client, req->server,
                       req->till ? req->till : (krb5_timestamp)(now + 604800),
                       TKT_FLG_INITIAL, &ticket);
    if (ret)
        goto cleanup;

    memset(&lre, 0, sizeof(lre));
    lre.lr_type = KRB5_LRQ_NONE;
    lre.value = now;
    last_req[0] = &lre;
    last_req[1] = NULL;

    memset(&ekr, 0, sizeof(ekr));
    ekr.msg_type = KRB5_AS_REP;
    ekr.session = &g_s1key;
    ekr.last_req = last_req;
    ekr.nonce = req->nonce;
    ekr.key_exp = now + 604800;
    ekr.flags = TKT_FLG_INITIAL;
    ekr.times.authtime = now;
    ekr.times.starttime = now;
    ekr.times.endtime = req->till ? req->till : (krb5_timestamp)(now + 604800);
    ekr.times.renew_till = ekr.times.endtime;
    ekr.server = req->server;
    ekr.caddrs = NULL;
    ekr.enc_padata = NULL;

    ret = encode_krb5_enc_kdc_rep_part(&ekr, &der);
    if (ret)
        goto cleanup;
    ret = krb5_c_encrypt_length(g_ctx, pkey.enctype, der->length, &bodylen);
    if (ret)
        goto cleanup;
    enc.ciphertext.data = malloc(bodylen);
    if (enc.ciphertext.data == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    enc.ciphertext.length = bodylen;
    ret = krb5_c_encrypt(g_ctx, &pkey, KRB5_KEYUSAGE_AS_REP_ENCPART, NULL,
                         der, &enc);
    if (ret)
        goto cleanup;

    memset(&rep, 0, sizeof(rep));
    rep.msg_type = KRB5_AS_REP;
    rep.padata = NULL;
    rep.client = req->client;
    rep.ticket = &ticket;
    rep.enc_part = enc;

    ret = encode_krb5_as_rep(&rep, &out_der);
    if (ret == 0) {
        buf = malloc(out_der->length);
        if (buf != NULL) {
            memcpy(buf, out_der->data, out_der->length);
            *len_out = out_der->length;
        }
    }

cleanup:
    if (out_der != NULL)
        krb5_free_data(g_ctx, out_der);
    if (der != NULL)
        krb5_free_data(g_ctx, der);
    if (enc.ciphertext.data != NULL)
        krb5_free_data_contents(g_ctx, &enc.ciphertext);
    if (ticket.enc_part.ciphertext.data != NULL)
        krb5_free_data_contents(g_ctx, &ticket.enc_part.ciphertext);
    if (pkey.contents != NULL)
        krb5_free_keyblock_contents(g_ctx, &pkey);
    krb5_free_data_contents(g_ctx, &salt);
    if (req != NULL)
        krb5_free_kdc_req(g_ctx, req);
    return buf;
}

/* Compose a valid TGS-REP answering the decoded TGS request: decrypt the
 * presented TGT ticket with the krbtgt long-term key to recover the session
 * key, decrypt the authenticator (RFC 4120 usage 7), honour any subkey, and
 * issue a real service ticket encrypted in the keytab key so the acceptor
 * can decrypt it. */
static uint8_t *
compose_tgsrep(const krb5_data *reqder, size_t *len_out)
{
    krb5_error_code ret;
    krb5_kdc_req *req = NULL;
    krb5_ap_req *apreq = NULL;
    krb5_authenticator *auth = NULL;
    krb5_enc_tkt_part *tgttkt = NULL;
    krb5_kdc_rep rep;
    krb5_ticket ticket;
    krb5_enc_kdc_rep_part ekr;
    krb5_keyblock *replykey;
    krb5_data plain, *der = NULL, *out_der = NULL;
    krb5_enc_data enc;
    size_t bodylen;
    krb5_last_req_entry lre, *last_req[2];
    uint8_t *buf = NULL;
    time_t now = time(NULL);
    krb5_pa_data **pa;
    krb5_data apder;

    memset(&rep, 0, sizeof(rep));
    memset(&ticket, 0, sizeof(ticket));
    memset(&enc, 0, sizeof(enc));
    plain = empty_data();

    if (decode_krb5_tgs_req(reqder, &req) != 0) {
        return NULL;
    }

    /* Locate the PA-TGS-REQ AP-Req. */
    if (req->padata == NULL) {
        ret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
        goto cleanup;
    }
    for (pa = req->padata; *pa != NULL; pa++) {
        if ((*pa)->pa_type == KRB5_PADATA_TGS_REQ)
            break;
    }
    if (*pa == NULL) {
        ret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
        goto cleanup;
    }
    apder = make_data((*pa)->contents, (*pa)->length);
    ret = decode_krb5_ap_req(&apder, &apreq);
    if (ret != 0) {
        ret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
        goto cleanup;
    }

    /* Recover the TGT session key by decrypting the ticket with the
     * krbtgt long-term key (usage KDC_REP_TICKET). */
    plain.length = apreq->ticket->enc_part.ciphertext.length;
    plain.data = malloc(plain.length);
    if (plain.data == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    ret = krb5_c_decrypt(g_ctx, &g_tgtkey, KRB5_KEYUSAGE_KDC_REP_TICKET,
                         NULL, &apreq->ticket->enc_part, &plain);
    if (ret) {
        free(plain.data);
        plain = empty_data();
        goto cleanup;
    }
    ret = decode_krb5_enc_tkt_part(&plain, &tgttkt);
    zapfree(plain.data, plain.length);
    plain = empty_data();
    if (ret)
        goto cleanup;

    /* Decrypt the authenticator with the TGT session key (usage 7). */
    plain.length = apreq->authenticator.ciphertext.length;
    plain.data = malloc(plain.length);
    if (plain.data == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    ret = krb5_c_decrypt(g_ctx, tgttkt->session,
                         KRB5_KEYUSAGE_TGS_REQ_AUTH, NULL,
                         &apreq->authenticator, &plain);
    if (ret) {
        free(plain.data);
        plain = empty_data();
        goto cleanup;
    }
    ret = decode_krb5_authenticator(&plain, &auth);
    zapfree(plain.data, plain.length);
    plain = empty_data();
    if (ret)
        goto cleanup;

    /* RFC 4120: reply encrypted under the authenticator subkey (usage 9)
     * when present, else the TGT session key (usage 8). */
    if (auth->subkey != NULL) {
        replykey = auth->subkey;
        ret = 0;
    } else {
        replykey = tgttkt->session;
        ret = 0;
    }

    ret = build_ticket(&g_svckey, &g_s2key, tgttkt->client, req->server,
                       req->till ? req->till : (krb5_timestamp)(now + 604800),
                       0, &ticket);
    if (ret)
        goto cleanup;

    memset(&lre, 0, sizeof(lre));
    lre.lr_type = KRB5_LRQ_NONE;
    lre.value = now;
    last_req[0] = &lre;
    last_req[1] = NULL;

    memset(&ekr, 0, sizeof(ekr));
    ekr.msg_type = KRB5_TGS_REP;
    ekr.session = &g_s2key;
    ekr.last_req = last_req;
    ekr.nonce = req->nonce;
    ekr.key_exp = now + 604800;
    ekr.flags = 0;
    ekr.times.authtime = tgttkt->times.authtime;
    ekr.times.starttime = now;
    ekr.times.endtime = req->till ? req->till : (krb5_timestamp)(now + 604800);
    ekr.times.renew_till = ekr.times.endtime;
    ekr.server = req->server;
    ekr.caddrs = NULL;
    ekr.enc_padata = NULL;

    ret = encode_krb5_enc_kdc_rep_part(&ekr, &der);
    if (ret)
        goto cleanup;
    ret = krb5_c_encrypt_length(g_ctx, replykey->enctype, der->length,
                                &bodylen);
    if (ret)
        goto cleanup;
    enc.ciphertext.data = malloc(bodylen);
    if (enc.ciphertext.data == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }
    enc.ciphertext.length = bodylen;
    ret = krb5_c_encrypt(g_ctx, replykey, auth->subkey != NULL ?
                         KRB5_KEYUSAGE_TGS_REP_ENCPART_SUBKEY :
                         KRB5_KEYUSAGE_TGS_REP_ENCPART_SESSKEY,
                         NULL, der, &enc);
    if (ret)
        goto cleanup;

    rep.msg_type = KRB5_TGS_REP;
    rep.padata = NULL;
    rep.client = tgttkt->client;
    rep.ticket = &ticket;
    rep.enc_part = enc;

    ret = encode_krb5_tgs_rep(&rep, &out_der);
    if (ret == 0) {
        buf = malloc(out_der->length);
        if (buf != NULL) {
            memcpy(buf, out_der->data, out_der->length);
            *len_out = out_der->length;
        }
    }

cleanup:
    if (out_der != NULL)
        krb5_free_data(g_ctx, out_der);
    if (enc.ciphertext.data != NULL)
        krb5_free_data_contents(g_ctx, &enc.ciphertext);
    if (ticket.enc_part.ciphertext.data != NULL)
        krb5_free_data_contents(g_ctx, &ticket.enc_part.ciphertext);
    if (der != NULL)
        krb5_free_data(g_ctx, der);
    if (auth != NULL)
        krb5_free_authenticator(g_ctx, auth);
    if (tgttkt != NULL)
        krb5_free_enc_tkt_part(g_ctx, tgttkt);
    if (apreq != NULL)
        krb5_free_ap_req(g_ctx, apreq);
    if (req != NULL)
        krb5_free_kdc_req(g_ctx, req);
    return buf;
}

/* Produce the next reply for an incoming KDC request.  Stateless for valid
 * paths: the TGS exchange recovers the TGT session key from the presented
 * ticket itself. */
static void
serve_request(const uint8_t *req, size_t len, uint8_t **resp_out,
              size_t *resp_len_out)
{
    krb5_data d;

    *resp_out = NULL;
    *resp_len_out = 0;

    pthread_mutex_lock(&g_lock);
    g_script.served++;
    if (len > 0) {
        d = make_data((void *)req, len);
        switch (req[0] & 0x1f) {
        case 10:                        /* AS-REQ */
            *resp_out = compose_asrep(&d, resp_len_out);
            break;
        case 12:                        /* TGS-REQ */
            *resp_out = compose_tgsrep(&d, resp_len_out);
            break;
        default:
            break;
        }
    }
    if (*resp_out == NULL)          /* generic terminating reply */
        *resp_out = compose_error(FALLBACK_ERRCODE, resp_len_out);
    pthread_mutex_unlock(&g_lock);
}

/* Fake-KDC thread: serve both transports on the loopback port. */
static void *
server_thread(void *arg)
{
    uint8_t reqbuf[65536], lenbuf[4];
    struct sockaddr_storage ss;
    socklen_t sslen;
    fd_set fds;
    int maxfd, n, cfd, got, off;
    size_t resplen;
    uint32_t framelen;
    uint8_t *resp;

    pthread_detach(pthread_self());
    maxfd = (g_udp_fd > g_tcp_fd) ? g_udp_fd : g_tcp_fd;

    for (;;) {
        FD_ZERO(&fds);
        FD_SET(g_udp_fd, &fds);
        FD_SET(g_tcp_fd, &fds);
        if (select(maxfd + 1, &fds, NULL, NULL, NULL) < 0)
            continue;

        if (FD_ISSET(g_udp_fd, &fds)) {
            sslen = sizeof(ss);
            n = recvfrom(g_udp_fd, reqbuf, sizeof(reqbuf), 0,
                         (struct sockaddr *)&ss, &sslen);
            if (n < 1)
                continue;
            serve_request(reqbuf, (size_t)n, &resp, &resplen);
            if (resp != NULL) {
                sendto(g_udp_fd, resp, resplen, 0,
                       (struct sockaddr *)&ss, sslen);
                free(resp);
            }
        }

        if (FD_ISSET(g_tcp_fd, &fds)) {
            cfd = accept(g_tcp_fd, NULL, NULL);
            if (cfd < 0)
                continue;
            /* 4-byte big-endian length prefix, then the message. */
            for (got = 0, off = 0; got < 4; got += off) {
                off = read(cfd, lenbuf + got, 4 - got);
                if (off <= 0)
                    break;
            }
            if (got == 4) {
                framelen = ((uint32_t)lenbuf[0] << 24) |
                    ((uint32_t)lenbuf[1] << 16) |
                    ((uint32_t)lenbuf[2] << 8) | (uint32_t)lenbuf[3];
                if (framelen > 0 && framelen <= sizeof(reqbuf)) {
                    for (got = 0, off = 0; (size_t)got < framelen;
                         got += off) {
                        off = read(cfd, reqbuf + got, framelen - got);
                        if (off <= 0)
                            break;
                    }
                    if ((size_t)got == framelen) {
                        serve_request(reqbuf, framelen, &resp, &resplen);
                        if (resp != NULL) {
                            uint32_t hl = htonl(resplen);
                            memcpy(lenbuf, &hl, 4);
                            (void)write(cfd, lenbuf, 4);
                            (void)write(cfd, resp, resplen);
                            free(resp);
                        }
                    }
                }
            }
            shutdown(cfd, SHUT_WR);  /* FIN; client may still be reading */
            close(cfd);
        }
    }
    return NULL;
}

static krb5_ccache g_cc = NULL;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    char profpath[] = "/tmp/fuzz_gss_exchange_conf.XXXXXX";
    char ktpath[] = "/tmp/fuzz_gss_exchange.kt.XXXXXX";
    char prof[512], portstr[16];
    int fd, port;
    OM_uint32 jmin;
    pthread_t tid;
    krb5_error_code ret;
    krb5_data emptysalt = empty_data();
    krb5_data pw_tgt = make_data((char *)"TgtFuzzPassword1!", 17);
    krb5_data pw_svc = make_data((char *)"SvcFuzzPassword1!", 17);

    /* Bind the fake KDC's UDP and TCP listeners on loopback. */
    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    g_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_udp_fd < 0 || g_tcp_fd < 0)
        return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);
    addr.sin_port = 0;
    if (bind(g_udp_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        return 0;
    if (getsockname(g_udp_fd, (struct sockaddr *)&addr, &alen) != 0)
        return 0;
    port = ntohs(addr.sin_port);
    addr.sin_port = htons(port);
    if (bind(g_tcp_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        return 0;
    if (listen(g_tcp_fd, 4) != 0)
        return 0;

    snprintf(portstr, sizeof(portstr), "%d", port);
    snprintf(prof, sizeof(prof),
             "[libdefaults]\n"
             "  default_realm = %s\n"
             "  udp_preference_limit = 1\n"
             "  dns_lookup_kdc = false\n"
             "  dns_canonicalize_hostname = false\n"
             "  rdns = false\n"
             "[realms]\n"
             "  %s = {\n"
             "    kdc = 127.0.0.1:%s\n"
             "  }\n",
             FUZZ_REALM, FUZZ_REALM, portstr);
    fd = mkstemp(profpath);
    if (fd < 0)
        return 0;
    if ((size_t)write(fd, prof, strlen(prof)) != strlen(prof)) {
        close(fd);
        return 0;
    }
    close(fd);
    setenv("KRB5_CONFIG", profpath, 1);
    setenv("KRB5CCNAME", "MEMORY:fuzzgss", 1);
    setenv("KRB5RCACHETYPE", "none", 1);

    /* The GSS layer creates its own krb5 contexts which re-read KRB5_CONFIG,
     * so the profile file must stay on disk. */
    if (krb5_init_context(&g_ctx) != 0)
        return 0;
    if (krb5_parse_name(g_ctx, "user@" FUZZ_REALM, &g_princ) != 0)
        return 0;
    if (krb5_parse_name(g_ctx, "host@" FUZZ_REALM, &g_svcprinc) != 0)
        return 0;
    if (krb5_get_init_creds_opt_alloc(g_ctx, &g_opt) != 0)
        return 0;
    if (krb5_cc_resolve(g_ctx, "MEMORY:fuzzgss", &g_cc) != 0)
        return 0;
    if (krb5_cc_initialize(g_ctx, g_cc, g_princ) != 0)
        return 0;
    if (gss_acquire_cred(&jmin, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                         GSS_C_NO_OID_SET, GSS_C_INITIATE, &g_init_cred,
                         NULL, NULL) != GSS_S_COMPLETE)
        return 0;

    /* Long-term keys of the fake KDC's services and the in-ticket session
     * keys; all derived once, deterministically. */
    ret = krb5_c_string_to_key(g_ctx, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                               &pw_tgt, &emptysalt, &g_tgtkey);
    if (ret == 0)
        ret = krb5_c_string_to_key(g_ctx, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                                   &pw_svc, &emptysalt, &g_svckey);
    if (ret != 0)
        return 0;
    memset(&g_s1key, 0, sizeof(g_s1key));
    g_s1key.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
    g_s1key.length = 32;
    g_s1key.contents = malloc(g_s1key.length);
    if (g_s1key.contents == NULL)
        return 0;
    memset(g_s1key.contents, 0x31, g_s1key.length);
    memset(&g_s2key, 0, sizeof(g_s2key));
    g_s2key.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
    g_s2key.length = 32;
    g_s2key.contents = malloc(g_s2key.length);
    if (g_s2key.contents == NULL)
        return 0;
    memset(g_s2key.contents, 0x32, g_s2key.length);

    /* Synthesize the acceptor keytab. */
    fd = mkstemp(ktpath);
    if (fd < 0)
        return 0;
    close(fd);
    if (write_keytab(ktpath, ENCTYPE_AES256_CTS_HMAC_SHA1_96) != 0)
        return 0;
    setenv("KRB5_KTNAME", ktpath, 1);

    /* Initiator target name (single-component principal host@FZ, matching
     * the keytab entry the acceptor uses). */
    {
        gss_buffer_desc tn;
        tn.length = strlen("host@" FUZZ_REALM);
        tn.value = (char *)"host@" FUZZ_REALM;
        if (gss_import_name(&jmin, &tn, GSS_C_NT_USER_NAME, &g_target) !=
            GSS_S_COMPLETE)
            return 0;

    }

    memset(&g_script, 0, sizeof(g_script));
    if (pthread_create(&tid, NULL, server_thread, NULL) != 0)
        return 0;

    g_ready = 1;
    return 0;
}

extern int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    krb5_error_code ret;
    krb5_creds creds, in_creds, *out_creds = NULL;
    krb5_principal svc = NULL;
    OM_uint32 jmin, jmaj, iret, aret, itime, atime;
    gss_ctx_id_t ictx = GSS_C_NO_CONTEXT, actx = GSS_C_NO_CONTEXT;
    gss_buffer_desc itok_in = GSS_C_EMPTY_BUFFER, itok_out, atok_out;
    gss_buffer_desc msg, out, mic;
    gss_name_t src = GSS_C_NO_NAME;
    gss_cred_id_t deleg = GSS_C_NO_CREDENTIAL;
    gss_OID mech, amech;
    OM_uint32 iflags = GSS_C_MUTUAL_FLAG;
    int established = 0, rounds, conf_state = 0;
    size_t payload_len;
    const uint8_t *payload;

    if (!g_ready || size < kMinInputLength || size > kMaxInputLength)
        return 0;

    mech = (data[0] & 0x01) ? gss_mech_spnego : gss_mech_krb5;
    if (data[1] & 0x01)
        iflags |= GSS_C_REPLAY_FLAG;
    if (data[1] & 0x02)
        iflags |= GSS_C_SEQUENCE_FLAG;
    if (data[1] & 0x04)
        iflags |= GSS_C_CONF_FLAG;
    if (data[1] & 0x08)
        iflags |= GSS_C_INTEG_FLAG;
    payload_len = size - 4;
    payload = data + 4;
    if (payload_len == 0)
        payload = (const uint8_t *)"\0";

    pthread_mutex_lock(&g_lock);
    g_script.enctype_idx = data[2];
    g_script.served = 0;
    pthread_mutex_unlock(&g_lock);

    /* Client AS exchange (password flow) to fill the ccache with a TGT. */
    ret = krb5_get_init_creds_password(g_ctx, &creds, g_princ, FUZZ_PASSWORD,
                                       NULL, NULL, 0, NULL, g_opt);
    if (ret)
        return 0;
    if (krb5_cc_initialize(g_ctx, g_cc, g_princ) == 0) {
        krb5_cc_store_cred(g_ctx, g_cc, &creds);
        memset(&in_creds, 0, sizeof(in_creds));
        in_creds.client = g_princ;
        if (krb5_parse_name(g_ctx, "host@" FUZZ_REALM, &svc) == 0) {
            in_creds.server = svc;
            (void)krb5_get_credentials(g_ctx, 0, g_cc, &in_creds, &out_creds);
            if (out_creds != NULL) {
                krb5_free_cred_contents(g_ctx, out_creds);
                free(out_creds);
            }
            krb5_free_principal(g_ctx, svc);
        }
    }
    krb5_free_cred_contents(g_ctx, &creds);

    if (g_init_cred == GSS_C_NO_CREDENTIAL)
        return 0;

    /* Optional: feed attacker bytes straight into the acceptor. */
    if ((data[3] & 0x08) && payload_len > 0) {
        msg.length = payload_len;
        msg.value = (void *)payload;
        jmaj = gss_accept_sec_context(&jmin, &actx, GSS_C_NO_CREDENTIAL,
                                      &msg, GSS_C_NO_CHANNEL_BINDINGS, &src,
                                          &amech, &atok_out, &aret, &atime,
                                          &deleg);
        gss_release_buffer(&jmin, &atok_out);
        if (src != GSS_C_NO_NAME)
            gss_release_name(&jmin, &src);
        if (deleg != GSS_C_NO_CREDENTIAL)
            gss_release_cred(&jmin, &deleg);
        gss_delete_sec_context(&jmin, &actx, GSS_C_NO_BUFFER);
        actx = GSS_C_NO_CONTEXT;
    }

    /* Initiator/acceptor establishment loop. */
    for (rounds = 0; rounds < 12; rounds++) {
        jmaj = gss_init_sec_context(&jmin, g_init_cred, &ictx, g_target,
                                    mech, iflags, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS,
                                    itok_in.length ?
                                        (gss_buffer_t)&itok_in :
                                        GSS_C_NO_BUFFER,
                                    NULL, &itok_out, &iret, &itime);
        gss_release_buffer(&jmin, &itok_in);
        itok_in.length = 0;
        itok_in.value = NULL;
        if (GSS_ERROR(jmaj)) {
            break;
        }
        if (itok_out.length == 0) {
            established = (jmaj == GSS_S_COMPLETE);
            break;
        }
        jmaj = gss_accept_sec_context(&jmin, &actx, GSS_C_NO_CREDENTIAL,
                                      &itok_out, GSS_C_NO_CHANNEL_BINDINGS,
                                      &src,
                                          &amech, &atok_out, &aret, &atime,
                                          &deleg);
        gss_release_buffer(&jmin, &itok_out);
        if (src != GSS_C_NO_NAME) {
            gss_release_name(&jmin, &src);
            src = GSS_C_NO_NAME;
        }
        if (deleg != GSS_C_NO_CREDENTIAL) {
            gss_release_cred(&jmin, &deleg);
            deleg = GSS_C_NO_CREDENTIAL;
        }
        if (GSS_ERROR(jmaj))
            break;
        established = (jmaj == GSS_S_COMPLETE);
        itok_in = atok_out;
        if (itok_in.length == 0)
            break;
    }
    gss_release_buffer(&jmin, &itok_in);
    itok_in.length = 0;
    itok_in.value = NULL;

    /* Post-establishment operations against both contexts. */
    if (established) {
        msg.length = payload_len > 0 ? payload_len : 1;
        msg.value = (void *)payload;
        if (data[3] & 0x01) {
            gss_buffer_desc uout = GSS_C_EMPTY_BUFFER;
            jmaj = gss_wrap(&jmin, ictx, (data[1] & 0x04) ? 1 : 0,
                            GSS_C_QOP_DEFAULT, &msg, &conf_state, &out);
            if (jmaj == GSS_S_COMPLETE) {
                (void)gss_unwrap(&jmin, actx, &out, &uout, &conf_state, NULL);
                gss_release_buffer(&jmin, &out);
                gss_release_buffer(&jmin, &uout);
            }
            jmaj = gss_wrap(&jmin, actx, 0, GSS_C_QOP_DEFAULT, &msg,
                            &conf_state, &out);
            if (jmaj == GSS_S_COMPLETE) {
                (void)gss_unwrap(&jmin, ictx, &out, &uout, &conf_state, NULL);
                gss_release_buffer(&jmin, &out);
                gss_release_buffer(&jmin, &uout);
            }
        }
        if (data[3] & 0x10) {
            /* IOV-based wrap/unwrap (DCE-style) in both directions: this is
             * the per-message path through k5unsealiov/util_crypt. */
            gss_iov_buffer_desc iov[4];
            OM_uint32 msz = 0;

            iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
            iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
            iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
            iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
            iov[1].buffer.length = msg.length;
            if (gss_wrap_iov_length(&jmin, ictx, 1, GSS_C_QOP_DEFAULT,
                                    NULL, iov, 4) == GSS_S_COMPLETE) {
                /* wrap_iov_length may adjust the DATA buffer length to the
                 * padded size; honour whatever it settled on. */
                size_t dlen = iov[1].buffer.length;
                for (int i = 0; i < 4; i++) {
                    if (iov[i].buffer.value == NULL &&
                        iov[i].buffer.length > 0)
                        iov[i].buffer.value = malloc(iov[i].buffer.length);
                }
                if (iov[1].buffer.value == NULL)
                    iov[1].buffer.value = malloc(dlen > 0 ? dlen : 1);
                memcpy(iov[1].buffer.value, msg.value,
                       msg.length <= dlen ? msg.length : dlen);
                if (gss_wrap_iov(&jmin, ictx, 1, GSS_C_QOP_DEFAULT, &msz,
                                 iov, 4) == GSS_S_COMPLETE) {
                    (void)gss_unwrap_iov(&jmin, actx, &conf_state, NULL,
                                         iov, 4);
                }
                for (int i = 0; i < 4; i++) {
                    if (iov[i].buffer.value != NULL) {
                        memset(iov[i].buffer.value, 0,
                               iov[i].buffer.length);
                        free(iov[i].buffer.value);
                        iov[i].buffer.value = NULL;
                    }
                }
            }
        }
        if (data[3] & 0x02) {
            jmaj = gss_get_mic(&jmin, ictx, GSS_C_QOP_DEFAULT, &msg, &mic);
            if (jmaj == GSS_S_COMPLETE) {
                (void)gss_verify_mic(&jmin, actx, &msg, &mic, NULL);
                gss_release_buffer(&jmin, &mic);
            }
        }
        if (data[3] & 0x04) {
            jmaj = gss_export_sec_context(&jmin, &ictx, &out);
            if (jmaj == GSS_S_COMPLETE) {
                gss_delete_sec_context(&jmin, &ictx, GSS_C_NO_BUFFER);
                (void)gss_import_sec_context(&jmin, &out, &ictx);
                gss_release_buffer(&jmin, &out);
            }
        }
        (void)gss_inquire_context(&jmin, ictx, NULL, NULL, NULL, NULL, NULL,
                                  NULL, NULL);
        (void)gss_inquire_context(&jmin, actx, NULL, NULL, NULL, NULL, NULL,
                                  NULL, NULL);
    }

    if (ictx != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&jmin, &ictx, GSS_C_NO_BUFFER);
    if (actx != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&jmin, &actx, GSS_C_NO_BUFFER);
    return 0;
}
