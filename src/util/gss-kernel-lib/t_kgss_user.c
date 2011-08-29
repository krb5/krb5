/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* util/gss-kernel-lib/t_kgss_user.c - Userspace portion of test program */
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
 * This program is run from t_kgss.py.  It establishes initiator and acceptor
 * contexts, then exports the acceptor context to a child program running
 * t_kgss_kernel, which is linked against libkgss.a.  Wrap, MIC, and IOV tokens
 * are then exchanged with the child process to test the libkgss functionality.
 */

#include "k5-int.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <gssapi/gssapi_krb5.h>
#include "t_kgss_common.h"

/* If major represents an error, display an error message and exit. */
static void
check(OM_uint32 major, OM_uint32 minor, const char *fn)
{
    OM_uint32 msg_ctx, tmpmin;
    gss_buffer_desc msg;

    if (!GSS_ERROR(major))
        return;
    fprintf(stderr, "%s: major %u, minor %u\n", fn, major, minor);
    gss_display_status(&tmpmin, minor, GSS_C_MECH_CODE, GSS_C_NULL_OID,
                       &msg_ctx, &msg);
    fprintf(stderr, "%.*s\n", (int)msg.length, (char *)msg.value);
    exit(1);
}

/* Establish initiator and acceptor security krb5 contexts using default
 * initiator/acceptor creds and a target krb5 principal named tprinc. */
static void
establish_contexts(const char *tprinc, gss_ctx_id_t *initiator_out,
                   gss_ctx_id_t *acceptor_out)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf, itoken, rtoken;
    gss_name_t target_name;
    gss_ctx_id_t initiator = GSS_C_NO_CONTEXT, acceptor = GSS_C_NO_CONTEXT;

    /* Import the target principal. */
    buf.value = (void *)tprinc;
    buf.length = strlen(tprinc);
    major = gss_import_name(&minor, &buf, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
                            &target_name);
    check(major, minor, "gss_import_name");

    /* Create initiator context and get initiator token. */
    itoken.value = NULL;
    itoken.length = 0;
    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &initiator,
                                 target_name, (gss_OID)gss_mech_krb5,
                                 GSS_C_MUTUAL_FLAG, GSS_C_INDEFINITE,
                                 GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                 NULL, &itoken, NULL, NULL);
    check(major, minor, "gss_init_sec_context(1)");
    assert(major == GSS_S_CONTINUE_NEEDED);

    /* Create acceptor context and get response token. */
    rtoken.value = NULL;
    rtoken.length = 0;
    major = gss_accept_sec_context(&minor, &acceptor, GSS_C_NO_CREDENTIAL,
                                   &itoken, GSS_C_NO_CHANNEL_BINDINGS,
                                   NULL, NULL, &rtoken, NULL, NULL, NULL);
    check(major, minor, "gss_accept_sec_context");
    assert(major == GSS_S_COMPLETE);

    /* Complete initiator context using response token. */
    gss_release_buffer(&minor, &itoken);
    itoken.value = NULL;
    itoken.length = 0;
    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &initiator,
                                 target_name, (gss_OID)gss_mech_krb5,
                                 GSS_C_MUTUAL_FLAG, GSS_C_INDEFINITE,
                                 GSS_C_NO_CHANNEL_BINDINGS, &rtoken,
                                 NULL, &itoken, NULL, NULL);
    check(major, minor, "gss_init_sec_context(2)");
    assert(major == GSS_S_COMPLETE);
    gss_release_buffer(&minor, &rtoken);
    gss_release_buffer(&minor, &itoken);

    *initiator_out = initiator;
    *acceptor_out = acceptor;
}

/* Start t_kgss_kernel in a child process with input and output pipes. */
static void
start_child(int *to_child_out, int *from_child_out, pid_t *pid_out)
{
    pid_t pid;
    int stdin_pipe[2], stdout_pipe[2];

    assert(pipe(stdin_pipe) == 0);
    assert(pipe(stdout_pipe) == 0);
    pid = fork();
    if (pid == 0) {
        /* Child. */
        dup2(stdin_pipe[0], STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdin_pipe[0]);
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        execl("./t_kgss_kernel", "./t_kgss_kernel", (char *)NULL);
        _exit(1);
    }
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);
    *to_child_out = stdin_pipe[1];
    *from_child_out = stdout_pipe[0];
    *pid_out = pid;
}

#define WRITE(b, d) krb5int_buf_add_len(b, (char *)&d, sizeof(d))

/* Add the fields of lkey to bufp. */
static void
add_lucid_key(struct k5buf *bufp, const gss_krb5_lucid_key_t *lkey)
{
    WRITE(bufp, lkey->type);
    WRITE(bufp, lkey->length);
    krb5int_buf_add_len(bufp, lkey->data, lkey->length);
}

/* Using a machine-dependent format, marshal the fields of lctx into an
 * allocated buffer. */
static void
marshal_lucid_context(const gss_krb5_lucid_context_v1_t *lctx,
                      unsigned char **data_out, size_t *len_out)
{
    struct k5buf buf;

    krb5int_buf_init_dynamic(&buf);
    WRITE(&buf, lctx->version);
    WRITE(&buf, lctx->initiate);
    WRITE(&buf, lctx->endtime);
    WRITE(&buf, lctx->send_seq);
    WRITE(&buf, lctx->recv_seq);
    WRITE(&buf, lctx->protocol);
    if (lctx->protocol == 0) {
        WRITE(&buf, lctx->rfc1964_kd.sign_alg);
        WRITE(&buf, lctx->rfc1964_kd.seal_alg);
        add_lucid_key(&buf, &lctx->rfc1964_kd.ctx_key);
    } else if (lctx->protocol == 1) {
        WRITE(&buf, lctx->cfx_kd.have_acceptor_subkey);
        add_lucid_key(&buf, &lctx->cfx_kd.ctx_key);
        if (lctx->cfx_kd.have_acceptor_subkey)
            add_lucid_key(&buf, &lctx->cfx_kd.acceptor_subkey);
    } else
        abort();
    assert(krb5int_buf_data(&buf) != NULL);
    *data_out = (unsigned char *)krb5int_buf_data(&buf);
    *len_out = krb5int_buf_len(&buf);
}

/* Export ctx as a lucid context, marshal it, and write it to fd. */
static void
send_lucid_context(gss_ctx_id_t ctx, int fd)
{
    OM_uint32 major, minor;
    void *result;
    gss_krb5_lucid_context_v1_t *lctx;
    unsigned char *data;
    size_t len;

    major = gss_krb5_export_lucid_sec_context(&minor, &ctx, 1, &result);
    check(major, minor, "gss_krb5_export_lucid_sec_context");
    lctx = result;
    marshal_lucid_context(lctx, &data, &len);
    send_data(fd, data, len);
    free(data);
}

/* Create a GSS wrap token of the text "userwrap" and send it to fd. */
static void
send_wrap_token(gss_ctx_id_t ctx, int fd)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf, wrapped;

    buf.value = "userwrap";
    buf.length = 8;
    major = gss_wrap(&minor, ctx, 1, GSS_C_QOP_DEFAULT, &buf, NULL, &wrapped);
    check(major, minor, "gss_wrap");
    send_data(fd, wrapped.value, wrapped.length);
    gss_release_buffer(&minor, &wrapped);
}

/* Create a MIC token for the text "usermic" and send it to fd. */
static void
send_mic_token(gss_ctx_id_t ctx, int fd)
{
    OM_uint32 major, minor;
    gss_buffer_desc buf, mic;

    buf.value = "usermic";
    buf.length = 7;
    major = gss_get_mic(&minor, ctx, GSS_C_QOP_DEFAULT, &buf, &mic);
    check(major, minor, "gss_get_mic");
    send_data(fd, mic.value, mic.length);
    gss_release_buffer(&minor, &mic);
}

/* Create an IOV token for "userwrapmic", wrapping only the "wrap" part, and
 * send the header/data/padding/trailer buffers to fd. */
static void
send_iov_token(gss_ctx_id_t ctx, int fd)
{
    OM_uint32 major, minor;
    gss_iov_buffer_desc iov[6];
    char *buf, *p;

    /* Lay out skeleton IOVs and compute header, padding, trailer lengths. */
    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].buffer.value = NULL;
    iov[0].buffer.length = 0;
    iov[1].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
    iov[1].buffer.value = "user";
    iov[1].buffer.length = 4;
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
    major = gss_wrap_iov_length(&minor, ctx, 1, GSS_C_QOP_DEFAULT, NULL,
                                iov, 6);
    check(major, minor, "gss_wrap_iov_length");

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
    major = gss_wrap_iov(&minor, ctx, 1, GSS_C_QOP_DEFAULT, NULL, iov, 6);
    check(major, minor, "gss_wrap_iov");
    send_data(fd, iov[0].buffer.value, iov[0].buffer.length);
    send_data(fd, iov[2].buffer.value, iov[2].buffer.length);
    send_data(fd, iov[4].buffer.value, iov[4].buffer.length);
    send_data(fd, iov[5].buffer.value, iov[5].buffer.length);
    free(buf);
}

/* Read a wrap token from fd and verify that it says "kernelwrap". */
static void
read_wrap_token(gss_ctx_id_t ctx, int fd)
{
    OM_uint32 major, minor;
    gss_buffer_desc wrapped, buf;

    read_data(fd, &wrapped.value, &wrapped.length);
    major = gss_unwrap(&minor, ctx, &wrapped, &buf, NULL, NULL);
    check(major, minor, "gss_unwrap");
    assert(buf.length == 10 && memcmp(buf.value, "kernelwrap", 10) == 0);
    gss_release_buffer(&minor, &buf);
    free(wrapped.value);
}

/* Read a MIC token from fd and verify that it was for "kernelmic". */
static void
read_mic_token(gss_ctx_id_t ctx, int fd)
{
    OM_uint32 major, minor;
    gss_buffer_desc mic, buf;

    read_data(fd, &mic.value, &mic.length);
    buf.value = "kernelmic";
    buf.length = 9;
    major = gss_verify_mic(&minor, ctx, &buf, &mic, NULL);
    check(major, minor, "gss_verify_mic");
    free(mic.value);
}

/* Read an IOV token from fd and verify that it is for "kernelwrapmic" with
 * only the "wrap" part wrapped. */
static void
read_iov_token(gss_ctx_id_t ctx, int fd)
{
    OM_uint32 major, minor;
    gss_iov_buffer_desc iov[6];

    /* Read in buffers and lay out the IOVs. */
    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    read_data(fd, &iov[0].buffer.value, &iov[0].buffer.length);
    iov[1].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
    iov[1].buffer.value = "kernel";
    iov[1].buffer.length = 6;
    iov[2].type = GSS_IOV_BUFFER_TYPE_DATA;
    read_data(fd, &iov[2].buffer.value, &iov[2].buffer.length);
    iov[3].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
    iov[3].buffer.value = "mic";
    iov[3].buffer.length = 3;
    iov[4].type = GSS_IOV_BUFFER_TYPE_PADDING;
    read_data(fd, &iov[4].buffer.value, &iov[4].buffer.length);
    iov[5].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    read_data(fd, &iov[5].buffer.value, &iov[5].buffer.length);

    /* Unwrap and check the data contents. */
    major = gss_unwrap_iov(&minor, ctx, NULL, NULL, iov, 6);
    check(major, minor, "gss_unwrap_iov");
    assert(iov[2].buffer.length == 4);
    assert(memcmp(iov[2].buffer.value, "wrap", 4) == 0);

    free(iov[0].buffer.value);
    free(iov[2].buffer.value);
    free(iov[4].buffer.value);
    free(iov[5].buffer.value);
}

/* Delete the security context ctx. */
static void
cleanup_context(gss_ctx_id_t ctx)
{
    OM_uint32 major, minor;

    major = gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
    check(major, minor, "gss_delete_sec_context");
}

int
main(int argc, char **argv)
{
    gss_ctx_id_t initiator, acceptor;
    int to_child, from_child, status;
    pid_t child_pid;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s target-princ\n", argv[0]);
        return 1;
    }

    establish_contexts(argv[1], &initiator, &acceptor);
    start_child(&to_child, &from_child, &child_pid);

    send_lucid_context(acceptor, to_child);
    read_ack(from_child);
    send_wrap_token(initiator, to_child);
    read_ack(from_child);
    send_mic_token(initiator, to_child);
    read_ack(from_child);
    send_iov_token(initiator, to_child);
    read_ack(from_child);

    read_wrap_token(initiator, from_child);
    send_ack(to_child);
    read_mic_token(initiator, from_child);
    send_ack(to_child);
    read_iov_token(initiator, from_child);
    send_ack(to_child);

    cleanup_context(initiator);
    close(to_child);
    close(from_child);
    assert(wait(&status) == child_pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}
