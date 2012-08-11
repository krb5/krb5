/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* util/gss-kernel-lib/t_kgss_kernel.c - Kernel portion of test program */
/*
 * Copyright (C) 2011 by the Massachusetts Institute of Technology.
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
 */

/*
 * This program links against libkgss.a and is run as a child process of
 * t_kgss_user.  It receives an exported acceptor context from its parent and
 * then exchanges wrap, MIC, and IOV tokens with the parent.
 */

#include "k5-int.h"
#include <unistd.h>
#include "gssapi_krb5.h"
#include "gssapiP_krb5.h"
#include "kernel_gss.h"
#include "t_kgss_common.h"

/* If major represents an error, display an error message and exit. */
static void
check(OM_uint32 major, OM_uint32 minor, const char *fn)
{
    if (!GSS_ERROR(major))
        return;
    fprintf(stderr, "t_kgss_kernel: %s: major %u, minor %u\n", fn, major,
            minor);
    /* libkgss doesn't have gss_display_status. */
    exit(1);
}

#define READ(p, f) (memcpy(&f, p, sizeof(f)), p += sizeof(f))

/* Read fields from p into lkey and return the updated pointer. */
static const unsigned char *
read_lucid_key(const unsigned char *p, gss_krb5_lucid_key_t *lkey)
{
    READ(p, lkey->type);
    READ(p, lkey->length);
    lkey->data = malloc(lkey->length);
    assert(lkey->data != NULL);
    memcpy(lkey->data, p, lkey->length);
    return p + lkey->length;
}

/* Read a data packet from stdin, unmarshal it into a lucid context, and import
 * the lucid context into a GSS-krb5 acceptor context. */
static void
read_lucid_context(gss_ctx_id_t *ctx_out)
{
    void *data;
    size_t len;
    const unsigned char *p;
    gss_krb5_lucid_context_v1_t lctx;
    OM_uint32 major, minor;

    /* No length checking; totally unsafe outside of this test program. */
    read_data(STDIN_FILENO, &data, &len);
    p = data;
    READ(p, lctx.version);
    READ(p, lctx.initiate);
    READ(p, lctx.endtime);
    READ(p, lctx.send_seq);
    READ(p, lctx.recv_seq);
    READ(p, lctx.protocol);
    if (lctx.protocol == 0) {
        READ(p, lctx.rfc1964_kd.sign_alg);
        READ(p, lctx.rfc1964_kd.seal_alg);
        p = read_lucid_key(p, &lctx.rfc1964_kd.ctx_key);
    } else if (lctx.protocol == 1) {
        READ(p, lctx.cfx_kd.have_acceptor_subkey);
        p = read_lucid_key(p, &lctx.cfx_kd.ctx_key);
        if (lctx.cfx_kd.have_acceptor_subkey)
            p = read_lucid_key(p, &lctx.cfx_kd.acceptor_subkey);
    } else
        abort();

    major = krb5_gss_import_lucid_sec_context(&minor, &lctx, ctx_out);
    check(major, minor, "krb5_gss_import_lucid_sec_context");
}

/* Read a wrap token from stdin and verify that it says "userwrap". */
static void
read_wrap_token(gss_ctx_id_t ctx)
{
    OM_uint32 major, minor;
    gss_buffer_desc wrapped, buf;

    read_data(STDIN_FILENO, &wrapped.value, &wrapped.length);
    major = krb5_gss_unwrap(&minor, ctx, &wrapped, &buf, NULL, NULL);
    check(major, minor, "krb5_gss_unwrap");
    assert(buf.length == 8 && memcmp(buf.value, "userwrap", 8) == 0);
    gssalloc_free(buf.value);
    free(wrapped.value);
}

/* Read a MIC token from stdin and verify that it is for "usermic". */
static void
read_mic_token(gss_ctx_id_t ctx)
{
    OM_uint32 major, minor;
    gss_buffer_desc mic, buf;

    read_data(STDIN_FILENO, &mic.value, &mic.length);
    buf.value = "usermic";
    buf.length = 7;
    major = krb5_gss_verify_mic(&minor, ctx, &buf, &mic, NULL);
    check(major, minor, "krb5_gss_verify_mic");
    free(mic.value);
}

/* Read an IOV token from stdin and verify that it is for "userwrapmic" with
 * only the "wrap" part wrapped. */
static void
read_iov_token(gss_ctx_id_t ctx)
{
    OM_uint32 major, minor;
    gss_iov_buffer_desc iov[6];

    /* Read in buffers and lay out the IOVs. */
    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    read_data(STDIN_FILENO, &iov[0].buffer.value, &iov[0].buffer.length);
    iov[1].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
    iov[1].buffer.value = "user";
    iov[1].buffer.length = 4;
    iov[2].type = GSS_IOV_BUFFER_TYPE_DATA;
    read_data(STDIN_FILENO, &iov[2].buffer.value, &iov[2].buffer.length);
    iov[3].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
    iov[3].buffer.value = "mic";
    iov[3].buffer.length = 3;
    iov[4].type = GSS_IOV_BUFFER_TYPE_PADDING;
    read_data(STDIN_FILENO, &iov[4].buffer.value, &iov[4].buffer.length);
    iov[5].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    read_data(STDIN_FILENO, &iov[5].buffer.value, &iov[5].buffer.length);

    /* Unwrap and check the data contents. */
    major = krb5_gss_unwrap_iov(&minor, ctx, NULL, NULL, iov, 6);
    check(major, minor, "gss_unwrap_iov");
    assert(iov[2].buffer.length == 4);
    assert(memcmp(iov[2].buffer.value, "wrap", 4) == 0);

    free(iov[0].buffer.value);
    free(iov[2].buffer.value);
    free(iov[4].buffer.value);
    free(iov[5].buffer.value);
}

/* Create a wrap token for the text "kernelwrap" and send it to stdout. */
static void
send_wrap_token(gss_ctx_id_t ctx)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf, wrapped;

    buf.value = "kernelwrap";
    buf.length = 10;
    major = krb5_gss_wrap(&minor, ctx, 1, GSS_C_QOP_DEFAULT, &buf, NULL,
                          &wrapped);
    check(major, minor, "krb5_gss_wrap");
    send_data(STDOUT_FILENO, wrapped.value, wrapped.length);
    gssalloc_free(wrapped.value);
}

/* Create a wrap token for the text "kernelmic" and send it to stdout. */
static void
send_mic_token(gss_ctx_id_t ctx)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf, mic;

    buf.value = "kernelmic";
    buf.length = 9;
    major = krb5_gss_get_mic(&minor, ctx, GSS_C_QOP_DEFAULT, &buf, &mic);
    check(major, minor, "krb5_gss_get_mic");
    send_data(STDOUT_FILENO, mic.value, mic.length);
    gssalloc_free(mic.value);
}

/* Create an IOV token for "kernelwrapmic", wrapping only the "wrap" part, and
 * send the header/data/padding/trailer buffers to stdout. */
static void
send_iov_token(gss_ctx_id_t ctx)
{
    OM_uint32 major, minor;
    gss_iov_buffer_desc iov[6];
    char *buf, *p;

    /* Lay out skeleton IOVs and compute header, padding, trailer lengths. */
    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].buffer.value = NULL;
    iov[0].buffer.length = 0;
    iov[1].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
    iov[1].buffer.value = "kernel";
    iov[1].buffer.length = 6;
    iov[2].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[2].buffer.value = "wrap";
    iov[2].buffer.length = 4;
    iov[3].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
    iov[3].buffer.value = "mic";
    iov[3].buffer.length = 3;
    iov[4].type = GSS_IOV_BUFFER_TYPE_PADDING;
    iov[4].buffer.value = NULL;
    iov[4].buffer.length = 0;
    iov[5].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    iov[5].buffer.value = NULL;
    iov[5].buffer.length = 0;
    major = krb5_gss_wrap_iov_length(&minor, ctx, 1, GSS_C_QOP_DEFAULT, NULL,
                                     iov, 6);
    check(major, minor, "krb5_gss_wrap_iov_length");

    /* Create a payload and set header/data/padding/trailer IOV pointers. */
    buf = malloc(iov[0].buffer.length + iov[2].buffer.length +
                 iov[4].buffer.length + iov[5].buffer.length);
    assert(buf != NULL);
    p = buf;
    iov[0].buffer.value = p;
    p += iov[0].buffer.length;
    memcpy(p, "wrap", 4);
    iov[2].buffer.value = p;
    p += iov[2].buffer.length;
    iov[4].buffer.value = p;
    p += iov[4].buffer.length;
    iov[5].buffer.value = p;

    /* Wrap the payload and send it to fd in chunks. */
    major = krb5_gss_wrap_iov(&minor, ctx, 1, GSS_C_QOP_DEFAULT, NULL, iov, 6);
    check(major, minor, "gss_wrap_iov");
    send_data(STDOUT_FILENO, iov[0].buffer.value, iov[0].buffer.length);
    send_data(STDOUT_FILENO, iov[2].buffer.value, iov[2].buffer.length);
    send_data(STDOUT_FILENO, iov[4].buffer.value, iov[4].buffer.length);
    send_data(STDOUT_FILENO, iov[5].buffer.value, iov[5].buffer.length);
    free(buf);
}

/* Delete the krb5 security context ctx. */
static void
cleanup_context(gss_ctx_id_t ctx)
{
    OM_uint32 major, minor;

    major = krb5_gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
    check(major, minor, "gss_delete_sec_context");
}

int
main(int argc, char **argv)
{
    gss_ctx_id_t acceptor;
    int dummy;

    /* Make the PRNG work since we're not using krb5_init_context. */
    krb5_c_random_os_entropy(NULL, 0, &dummy);

    read_lucid_context(&acceptor);
    send_ack(STDOUT_FILENO);
    read_wrap_token(acceptor);
    send_ack(STDOUT_FILENO);
    read_mic_token(acceptor);
    send_ack(STDOUT_FILENO);
    read_iov_token(acceptor);
    send_ack(STDOUT_FILENO);

    send_wrap_token(acceptor);
    read_ack(STDIN_FILENO);
    send_mic_token(acceptor);
    read_ack(STDIN_FILENO);
    send_iov_token(acceptor);
    read_ack(STDIN_FILENO);

    cleanup_context(acceptor);
    return 0;
}
