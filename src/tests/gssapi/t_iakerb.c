/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/gssapi/t_iakerb.c - IAKERB tests */
/*
 * Copyright (C) 2024, 2025 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "k5-der.h"
#include "common.h"

/* Token IDs from lib/gssapi/krb5/gssapiP_krb5.h. */
#define TOK_AP_REQ 0x0100
#define TOK_IAKERB_PROXY 0x0501

/* Parse the RFC 2743 framing of tok.  Alias the mechanism OID into *oid_out
 * and return the two-byte token ID which follows it. */
static unsigned int
parse_token_header(gss_buffer_t tok, gss_OID_desc *oid_out)
{
    const unsigned char *p = tok->value, *end = p + tok->length;
    size_t lenlen;

    if (end - p < 2 || *p++ != 0x60)
        errout("Token lacks GSS framing");

    /* Skip the outer DER length; tok->length bounds the parse. */
    if (*p & 0x80) {
        lenlen = *p++ & 0x7F;
        if (lenlen > (size_t)(end - p))
            errout("Truncated token length");
        p += lenlen;
    } else {
        p++;
    }

    if (end - p < 2 || *p++ != 0x06)
        errout("Token lacks a mechanism OID");
    oid_out->length = *p++;
    if ((size_t)(end - p) < oid_out->length + 2)
        errout("Truncated token mechanism OID");
    oid_out->elements = (void *)p;
    p += oid_out->length;
    return (p[0] << 8) | p[1];
}

/* Decode the IAKERB-HEADER of proxy token tok, whose mechanism OID was
 * aliased into *oid by parse_token_header(), and return its header-flags. */
static krb5_flags
get_header_flags(gss_buffer_t tok, const gss_OID_desc *oid)
{
    const unsigned char *body, *end;
    struct k5input in, seq;
    krb5_iakerb_header *iah;
    krb5_data data;
    krb5_flags flags;

    /* The IAKERB-HEADER follows the two-byte token ID. */
    body = (const unsigned char *)oid->elements + oid->length + 2;
    end = (const unsigned char *)tok->value + tok->length;
    k5_input_init(&in, body, end - body);
    if (!k5_der_get_value(&in, 0x30, &seq))
        errout("IAKERB proxy token lacks an IAKERB-HEADER");
    data = make_data((void *)body, seq.ptr + seq.len - body);
    if (decode_krb5_iakerb_header(&data, &iah) != 0)
        errout("Cannot decode IAKERB-HEADER");
    flags = iah->header_flags;
    krb5_free_iakerb_header(NULL, iah);
    return flags;
}

/*
 * Check the framing of an initiator token.  Once IAKERB proxy tokens have
 * been exchanged, the AP-REQ must use the krb5 OID; if the initiator skipped
 * straight to the AP exchange, it must use the IAKERB OID so that the
 * acceptor dispatches to the IAKERB mechanism.
 */
static void
check_init_token(gss_buffer_t tok, int *saw_proxy)
{
    gss_OID_desc oid;
    unsigned int tokid;

    if (tok->length == 0)
        return;

    tokid = parse_token_header(tok, &oid);
    if (tokid == TOK_IAKERB_PROXY) {
        if (!gss_oid_equal(&oid, &mech_iakerb))
            errout("IAKERB proxy token has the wrong mechanism OID");
        if (get_header_flags(tok, &oid) != 0)
            errout("Initiator sent IAKERB header-flags");
        *saw_proxy = 1;
    } else if (tokid == TOK_AP_REQ) {
        if (!gss_oid_equal(&oid, *saw_proxy ? &mech_krb5 : &mech_iakerb))
            errout("AP-REQ token has the wrong mechanism OID");
        printf("AP-REQ mech: %s\n", *saw_proxy ? "krb5" : "iakerb");
    } else {
        errout("Unexpected initiator token ID");
    }
}

/* Display the header-flags of an acceptor IAKERB proxy token, so that the
 * test script can check them for each response. */
static void
check_accept_token(gss_buffer_t tok)
{
    gss_OID_desc oid;

    if (tok->length == 0 || parse_token_header(tok, &oid) != TOK_IAKERB_PROXY)
        return;
    printf("IAKERB acceptor header-flags: %08x\n",
           (unsigned int)get_header_flags(tok, &oid));
}

/* Establish IAKERB contexts with mutual authentication, checking the framing
 * of each initiator token. */
static void
establish_iakerb(gss_cred_id_t icred, gss_cred_id_t acred, gss_name_t tname,
                 gss_ctx_id_t *ictx, gss_ctx_id_t *actx)
{
    OM_uint32 minor, imaj, amaj;
    gss_buffer_desc itok = GSS_C_EMPTY_BUFFER, atok = GSS_C_EMPTY_BUFFER;
    int saw_proxy = 0;

    *ictx = *actx = GSS_C_NO_CONTEXT;
    imaj = amaj = GSS_S_CONTINUE_NEEDED;
    for (;;) {
        (void)gss_release_buffer(&minor, &itok);
        imaj = gss_init_sec_context(&minor, icred, ictx, tname, &mech_iakerb,
                                    GSS_C_MUTUAL_FLAG, GSS_C_INDEFINITE,
                                    GSS_C_NO_CHANNEL_BINDINGS, &atok, NULL,
                                    &itok, NULL, NULL);
        check_gsserr("gss_init_sec_context", imaj, minor);
        check_init_token(&itok, &saw_proxy);
        if (amaj == GSS_S_COMPLETE)
            break;

        (void)gss_release_buffer(&minor, &atok);
        amaj = gss_accept_sec_context(&minor, actx, acred, &itok,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL,
                                      &atok, NULL, NULL, NULL);
        check_gsserr("gss_accept_sec_context", amaj, minor);
        check_accept_token(&atok);
        (void)gss_release_buffer(&minor, &itok);
        if (imaj == GSS_S_COMPLETE)
            break;
    }

    if (imaj != GSS_S_COMPLETE || amaj != GSS_S_COMPLETE)
        errout("One side wants to continue after the other is done");

    (void)gss_release_buffer(&minor, &itok);
    (void)gss_release_buffer(&minor, &atok);
}

int
main(int argc, char **argv)
{
    OM_uint32 major, minor;
    const char *password;
    gss_name_t iname, tname, aname;
    gss_cred_id_t icred, acred;
    gss_ctx_id_t ictx, actx;
    gss_buffer_desc pwbuf;

    if (argc != 5) {
        fprintf(stderr, "Usage: %s initiatorname password|- targetname "
                "acceptorname\n", argv[0]);
        return 1;
    }

    iname = import_name(argv[1]);
    password = argv[2];
    tname = import_name(argv[3]);
    aname = import_name(argv[4]);

    if (strcmp(password, "-") != 0) {
        pwbuf.value = (void *)password;
        pwbuf.length = strlen(password);
        major = gss_acquire_cred_with_password(&minor, iname, &pwbuf, 0,
                                               &mechset_iakerb, GSS_C_INITIATE,
                                               &icred, NULL, NULL);
        check_gsserr("gss_acquire_cred_with_password", major, minor);
    } else {
        major = gss_acquire_cred(&minor, iname, GSS_C_INDEFINITE,
                                 &mechset_iakerb, GSS_C_INITIATE, &icred, NULL,
                                 NULL);
        check_gsserr("gss_acquire_cred(iname)", major, minor);
    }

    major = gss_acquire_cred(&minor, aname, GSS_C_INDEFINITE, &mechset_iakerb,
                             GSS_C_ACCEPT, &acred, NULL, NULL);
    check_gsserr("gss_acquire_cred(aname)", major, minor);

    establish_iakerb(icred, acred, tname, &ictx, &actx);

    (void)gss_release_name(&minor, &iname);
    (void)gss_release_name(&minor, &tname);
    (void)gss_release_name(&minor, &aname);
    (void)gss_release_cred(&minor, &icred);
    (void)gss_release_cred(&minor, &acred);
    (void)gss_delete_sec_context(&minor, &ictx, NULL);
    (void)gss_delete_sec_context(&minor, &actx, NULL);
    return 0;
}
