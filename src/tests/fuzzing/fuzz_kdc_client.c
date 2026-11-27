/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/fuzzing/fuzz_kdc_client.c - fuzzing harness for the client-side
 * KDC exchange (get_in_tkt/get_creds/sendto_kdc/locate_kdc).
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
 * Threat model: the client-side Kerberos library must safely parse KDC
 * replies received over a hostile network path (a rogue KDC installed on a
 * captive portal, spoofed datagrams).  Those replies are parsed before any
 * authentication of the responder, so the attacker fully controls their
 * bytes: exactly the untrusted input this harness feeds in.
 *
 * The harness binds UDP and TCP listeners on 127.0.0.1 (no external egress;
 * the KDC address is pinned via a generated profile) and serves
 * fuzz-scripted replies to the exchanges driven by
 * krb5_get_init_creds_password() and krb5_get_credentials().  Reply modes:
 *   - raw: the fuzz bytes are the reply (attacker-controlled garbage);
 *   - error: a composed KRB-ERROR with a selectable protocol error code
 *     (KDC_ERR_PREAUTH_REQUIRED drives the preauth retry, and
 *     KRB_ERR_RESPONSE_TOO_BIG drives the UDP-to-TCP fallback);
 *   - asrep: a fully valid AS-REP composed with the library's own ASN.1
 *     encoders and crypto: the request is decoded for the nonce and client
 *     principal, the reply key is derived from the harness password with
 *     krb5_c_string_to_key over the same default salt the client derives
 *     (krb5_principal2salt), and the encrypted part carries an
 *     EncASRepPart echoing the nonce.  The client thus completes a real
 *     AS exchange and the credentials are stored in a MEMORY ccache, after
 *     which a TGS exchange is attempted via krb5_get_credentials().
 *
 * Input layout (minimum 4 bytes):
 *   byte 0: reply mode for the first request: 0 raw, 1 error, 2 AS-REP
 *   byte 1: reply mode for later requests:   0 generic error, 1 error,
 *                                            2 AS-REP
 *   byte 2: enctype selector for composed AS-REPs
 *   byte 3: error-code selector for composed errors
 *   bytes 4+: raw reply payload used by raw mode
 */

#include "autoconf.h"
#include <k5-int.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define kMinInputLength 4
#define kMaxInputLength 100000

#define FUZZ_REALM      "FZ"
#define FUZZ_PASSWORD   "FuzzPassword1!"

/* Reply-mode encodings for the first two input bytes. */
enum reply_mode { MODE_RAW = 0, MODE_ERROR = 1, MODE_ASREP = 2 };

/* Supported enctypes for composed AS-REPs (all in the default client
 * enctype list so the reply key can be derived from the password). */
static const krb5_enctype etype_table[] = {
    ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96,
    ENCTYPE_AES256_CTS_HMAC_SHA384_192, ENCTYPE_AES128_CTS_HMAC_SHA256_128
};
#define ETYPE_TABLE_LEN (sizeof(etype_table) / sizeof(etype_table[0]))

/* Protocol error codes for composed KRB-ERROR replies.  Only codes that
 * terminate or bound the client's exchange are used; referral-chasing codes
 * (WRONG_REALM / C_PRINCIPAL_UNKNOWN as a service error) would make the
 * client loop over realms and stall the run. */
static const krb5_ui_4 errcode_table[] = {
    KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_PREAUTH_FAILED, KDC_ERR_ENCTYPE_NOSUPP,
    KRB_ERR_RESPONSE_TOO_BIG, KDC_ERR_SVC_UNAVAILABLE
};
#define ERRCODE_TABLE_LEN \
    (sizeof(errcode_table) / sizeof(errcode_table[0]))

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

/* Harness state initialised once. */
static krb5_context g_ctx = NULL;
static krb5_principal g_princ = NULL;
static krb5_ccache g_cc = NULL;
static krb5_get_init_creds_opt *g_opt = NULL;
static int g_udp_fd = -1;
static int g_tcp_fd = -1;
static int g_ready = 0;

/* The fuzz-controlled reply script, replaced on each iteration and
 * consumed by the server thread.  raw[] holds the raw-mode payload. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct reply_script {
    int slot0_mode;
    int slot1_mode;
    int enctype_idx;
    int errcode_idx;
    uint8_t raw[65536];
    size_t raw_len;
    int served;
} g_script;

/* Allocate a copy of der as the reply buffer. */
static uint8_t *
copy_reply(const krb5_data *der, size_t *len_out)
{
    uint8_t *buf;

    buf = malloc(der->length);
    if (buf == NULL)
        return NULL;
    memcpy(buf, der->data, der->length);
    *len_out = der->length;
    return buf;
}

/* Compose a KRB-ERROR reply with the given protocol error code. */
static uint8_t *
compose_error(krb5_ui_4 code, size_t *len_out)
{
    krb5_error e;
    krb5_data *der = NULL;

    memset(&e, 0, sizeof(e));
    e.ctime = time(NULL);
    e.cusec = 0;
    e.susec = 0;
    e.stime = time(NULL);
    e.error = code;
    e.client = g_princ;
    e.server = g_princ;
    e.text = empty_data();
    e.e_data = empty_data();

    if (encode_krb5_error(&e, &der) != 0)
        return NULL;
    {
        uint8_t *buf = copy_reply(der, len_out);

        krb5_free_data(g_ctx, der);
        return buf;
    }
}

/* Compose a fully valid AS-REP answering the decoded request. */
static uint8_t *
compose_asrep(const krb5_data *reqder, size_t *len_out)
{
    krb5_error_code ret;
    krb5_kdc_req *req = NULL;
    krb5_kdc_rep rep;
    krb5_ticket tkt;
    krb5_enc_kdc_rep_part ekr;
    krb5_keyblock pkey, skey;
    krb5_data salt, *der = NULL, *out_der = NULL;
    krb5_last_req_entry lre, *last_req[2];
    size_t bodylen;
    krb5_enc_data enc;
    krb5_enctype etype;
    krb5_data pw = make_data((char *)FUZZ_PASSWORD, strlen(FUZZ_PASSWORD));
    uint8_t *buf = NULL;
    time_t now = time(NULL);

    memset(&pkey, 0, sizeof(pkey));
    memset(&skey, 0, sizeof(skey));
    memset(&enc, 0, sizeof(enc));
    memset(&tkt, 0, sizeof(tkt));
    salt = empty_data();

    ret = decode_krb5_as_req(reqder, &req);
    if (ret != 0)
        return NULL;

    etype = etype_table[g_script.enctype_idx % ETYPE_TABLE_LEN];

    /* Derive the reply key exactly like the client will: string2key over
     * the password and the default salt of the reply's client principal. */
    ret = krb5_principal2salt(g_ctx, req->client, &salt);
    if (ret)
        goto cleanup;
    ret = krb5_c_string_to_key(g_ctx, etype, &pw, &salt, &pkey);
    if (ret)
        goto cleanup;

    /* The session key inside the encrypted part (client never checks its
     * contents beyond length/enctype). */
    skey.magic = 0;
    skey.enctype = etype;
    skey.length = 32;
    skey.contents = malloc(skey.length);
    if (skey.contents == NULL)
        goto cleanup;
    memset(skey.contents, 0x5a, skey.length);

    /* Encrypted ticket bytes: opaque to the client during AS processing. */
    tkt.server = req->server;
    tkt.enc_part.enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
    tkt.enc_part.kvno = 1;
    tkt.enc_part.ciphertext.length = 64;
    tkt.enc_part.ciphertext.data = malloc(64);
    if (tkt.enc_part.ciphertext.data == NULL)
        goto cleanup;
    memset(tkt.enc_part.ciphertext.data, 0xa5, 64);

    /* last_req is a mandatory pointer in the ASN.1 encoder table; the real
     * KDC always emits at least one LRQ_NONE entry. */
    memset(&lre, 0, sizeof(lre));
    lre.lr_type = KRB5_LRQ_NONE;
    lre.value = now;
    last_req[0] = &lre;
    last_req[1] = NULL;

    memset(&ekr, 0, sizeof(ekr));
    ekr.msg_type = KRB5_AS_REP;
    ekr.session = &skey;
    ekr.last_req = last_req;
    ekr.nonce = req->nonce;
    ekr.key_exp = now + 604800;
    ekr.flags = TKT_FLG_INITIAL;
    ekr.times.authtime = now;
    ekr.times.starttime = now;
    /* The reply must not outlive the requested lifetime (verify_as_reply
     * rejects replies whose endtime is past the request's till). */
    ekr.times.endtime = req->till ? req->till : (krb5_timestamp)(now + 604800);
    ekr.times.renew_till = ekr.times.endtime;
    ekr.server = req->server;
    ekr.caddrs = NULL;
    ekr.enc_padata = NULL;

    ret = encode_krb5_enc_kdc_rep_part(&ekr, &der);
    if (ret)
        goto cleanup;

    /* The caller must size the ciphertext buffer before encrypting. */
    ret = krb5_c_encrypt_length(g_ctx, etype, der->length, &bodylen);
    if (ret)
        goto cleanup;
    enc.ciphertext.data = malloc(bodylen);
    if (enc.ciphertext.data == NULL)
        goto cleanup;
    enc.ciphertext.length = bodylen;
    ret = krb5_c_encrypt(g_ctx, &pkey, KRB5_KEYUSAGE_AS_REP_ENCPART, NULL,
                         der, &enc);
    if (ret)
        goto cleanup;

    memset(&rep, 0, sizeof(rep));
    rep.msg_type = KRB5_AS_REP;
    rep.padata = NULL;
    rep.client = req->client;
    rep.ticket = &tkt;
    rep.enc_part = enc;

    ret = encode_krb5_as_rep(&rep, &out_der);
    if (ret == 0)
        buf = copy_reply(out_der, len_out);

cleanup:
    if (out_der != NULL)
        krb5_free_data(g_ctx, out_der);
    if (der != NULL)
        krb5_free_data(g_ctx, der);
    if (enc.ciphertext.data != NULL)
        krb5_free_data_contents(g_ctx, &enc.ciphertext);
    if (tkt.enc_part.ciphertext.data != NULL)
        free(tkt.enc_part.ciphertext.data);
    if (skey.contents != NULL)
        free(skey.contents);
    if (pkey.contents != NULL)
        krb5_free_keyblock_contents(g_ctx, &pkey);
    krb5_free_data_contents(g_ctx, &salt);
    if (req != NULL)
        krb5_free_kdc_req(g_ctx, req);
    return buf;
}

/* Produce the next scripted reply for an incoming request. */
static void
serve_request(const uint8_t *req, size_t len, uint8_t **resp_out,
              size_t *resp_len_out)
{
    int mode;
    krb5_data d;

    *resp_out = NULL;
    *resp_len_out = 0;

    pthread_mutex_lock(&g_lock);
    mode = (g_script.served == 0) ? g_script.slot0_mode : g_script.slot1_mode;
    g_script.served++;

    switch (mode) {
    case MODE_RAW:
        if (g_script.raw_len > 0) {
            *resp_out = malloc(g_script.raw_len);
            if (*resp_out != NULL) {
                memcpy(*resp_out, g_script.raw, g_script.raw_len);
                *resp_len_out = g_script.raw_len;
            }
        }
        break;
    case MODE_ERROR:
        *resp_out = compose_error(errcode_table[g_script.errcode_idx %
                                                ERRCODE_TABLE_LEN],
                                  resp_len_out);
        break;
    case MODE_ASREP:
        /* Compose an AS-REP only for a syntactically tagged AS-REQ; other
         * messages get the generic error so the exchange terminates. */
        if (len > 0 && (req[0] & 0x1f) == 10) {
            d = make_data((void *)req, len);
            *resp_out = compose_asrep(&d, resp_len_out);
        }
        break;
    default:
        break;
    }
    if (*resp_out == NULL)          /* generic terminating reply */
        *resp_out = compose_error(KDC_ERR_S_PRINCIPAL_UNKNOWN, resp_len_out);
    pthread_mutex_unlock(&g_lock);
}

/* Fake-KDC thread: serve both transports on the loopback port. */
static void *
server_thread(void *arg)
{
    uint8_t reqbuf[65536], lenbuf[4], *resp;
    struct sockaddr_storage ss;
    socklen_t sslen;
    fd_set fds;
    int maxfd, n, cfd, got, off;
    size_t resplen;
    uint32_t framelen;

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
                            {
                                ssize_t w1 = write(cfd, lenbuf, 4);
                                ssize_t w2 = write(cfd, resp, resplen);
                            }
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

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    char profpath[] = "/tmp/fuzz_kdc_client.XXXXXX";
    char prof[512], portstr[16];
    int fd, port;
    pthread_t tid;

    /* Bind the fake KDC's UDP and TCP listeners on loopback. */
    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    g_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_udp_fd < 0 || g_tcp_fd < 0)
        return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);   /* 127.0.0.1, no egress */
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

    /* Profile pinning the realm's KDC to the loopback listener, with no
     * DNS discovery anywhere.  A small udp_preference_limit makes requests
     * travel over TCP first (with UDP fallback) to exercise both
     * transports. */
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
    setenv("KRB5CCNAME", "MEMORY:fuzzkdc", 1);

    if (krb5_init_context(&g_ctx) != 0)
        return 0;
    (void)unlink(profpath);
    if (krb5_parse_name(g_ctx, "user@" FUZZ_REALM, &g_princ) != 0)
        return 0;
    if (krb5_get_init_creds_opt_alloc(g_ctx, &g_opt) != 0)
        return 0;
    if (krb5_cc_resolve(g_ctx, "MEMORY:fuzzkdc", &g_cc) != 0)
        return 0;

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

    if (!g_ready || size < kMinInputLength || size > kMaxInputLength)
        return 0;

    /* Load this iteration's reply script. */
    pthread_mutex_lock(&g_lock);
    g_script.slot0_mode = data[0] % 3;
    g_script.slot1_mode = data[1] % 3;
    g_script.enctype_idx = data[2];
    g_script.errcode_idx = data[3];
    g_script.raw_len = size - 4;
    if (g_script.raw_len > sizeof(g_script.raw))
        g_script.raw_len = sizeof(g_script.raw);
    memcpy(g_script.raw, data + 4, g_script.raw_len);
    g_script.served = 0;
    pthread_mutex_unlock(&g_lock);

    ret = krb5_get_init_creds_password(g_ctx, &creds, g_princ, FUZZ_PASSWORD,
                                       NULL, NULL, 0, NULL, g_opt);
    if (ret) {
        return 0;
    }

    /* With a TGT in hand, attempt a service ticket to drive the TGS
     * exchange (get_creds.c) against the scripted replies. */
    if (krb5_cc_initialize(g_ctx, g_cc, g_princ) == 0) {
        krb5_cc_store_cred(g_ctx, g_cc, &creds);
        memset(&in_creds, 0, sizeof(in_creds));
        in_creds.client = g_princ;
        if (krb5_parse_name(g_ctx, "host/host.example.com@" FUZZ_REALM,
                            &svc) == 0) {
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
    return 0;
}
