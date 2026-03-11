/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/tls/k5tls/openssl.c - OpenSSL TLS module implementation */
/*
 * Copyright 2013,2014 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
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

#include "k5-int.h"
#include "k5-utf8.h"
#include "k5-tls.h"

#ifdef TLS_IMPL_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <dirent.h>

#if OPENSSL_VERSION_NUMBER < 0x40000000L
/*
 * OpenSSL 4.0 constifies the result of X509_STORE_CTX_get_current_cert() and
 * the input of X509_check_host() and X509_check_ip_asc().  For prior versions,
 * make the latter two functions accept const pointers via a cast.
 */
#define X509_check_host(a, b, c, d, e) X509_check_host((X509 *)a, b, c, d, e)
#define X509_check_ip_asc(a, b, c) X509_check_ip_asc((X509 *)a, b, c)
#endif

struct k5_tls_handle_st {
    SSL *ssl;
    char *servername;
};

static int ex_context_id = -1;
static int ex_handle_id = -1;

MAKE_INIT_FUNCTION(init_openssl);

int
init_openssl(void)
{
    ex_context_id = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    ex_handle_id = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    return 0;
}

static void
flush_errors(krb5_context context)
{
    unsigned long err;
    char buf[128];

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        TRACE_TLS_ERROR(context, buf);
    }
}

static krb5_boolean
check_cert_name_or_ip(const X509 *x, const char *expected_name)
{
    struct in_addr in;
    struct in6_addr in6;
    int r;

    if (inet_pton(AF_INET, expected_name, &in) != 0 ||
        inet_pton(AF_INET6, expected_name, &in6) != 0)
        r = X509_check_ip_asc(x, expected_name, 0);
    else
        r = X509_check_host(x, expected_name, 0, 0, NULL);
    return r == 1;
}

static int
verify_callback(int preverify_ok, X509_STORE_CTX *store_ctx)
{
    const X509 *x;
    SSL *ssl;
    BIO *bio;
    krb5_context context;
    int err, depth;
    k5_tls_handle handle;
    const char *cert = NULL, *errstr, *expected_name;
    size_t count;

    ssl = X509_STORE_CTX_get_ex_data(store_ctx,
                                     SSL_get_ex_data_X509_STORE_CTX_idx());
    context = SSL_get_ex_data(ssl, ex_context_id);
    handle = SSL_get_ex_data(ssl, ex_handle_id);
    assert(context != NULL && handle != NULL);
    /* We do have the peer's cert, right? */
    x = X509_STORE_CTX_get_current_cert(store_ctx);
    if (x == NULL) {
        TRACE_TLS_NO_REMOTE_CERTIFICATE(context);
        return 0;
    }
    /* Figure out where we are. */
    depth = X509_STORE_CTX_get_error_depth(store_ctx);
    if (depth < 0)
        return 0;
    /* If there's an error at this level that we're not ignoring, fail. */
    err = X509_STORE_CTX_get_error(store_ctx);
    if (err != X509_V_OK) {
        bio = BIO_new(BIO_s_mem());
        if (bio != NULL) {
            X509_NAME_print_ex(bio, X509_get_subject_name(x), 0, 0);
            count = BIO_get_mem_data(bio, &cert);
            errstr = X509_verify_cert_error_string(err);
            TRACE_TLS_CERT_ERROR(context, depth, count, cert, err, errstr);
            BIO_free(bio);
        }
        return 0;
    }
    /* If we're not looking at the peer, we're done and everything's ok. */
    if (depth != 0)
        return 1;
    /* Check if the name we expect to find is in the certificate. */
    expected_name = handle->servername;
    if (check_cert_name_or_ip(x, expected_name)) {
        TRACE_TLS_SERVER_NAME_MATCH(context, expected_name);
        return 1;
    } else {
        TRACE_TLS_SERVER_NAME_MISMATCH(context, expected_name);
    }
    /* The name didn't match. */
    return 0;
}

static krb5_error_code
load_anchor_file(X509_STORE *store, const char *path)
{
    FILE *fp;
    STACK_OF(X509_INFO) *sk = NULL;
    X509_INFO *xi;
    int i;

    fp = fopen(path, "r");
    if (fp == NULL)
        return errno;
    sk = PEM_X509_INFO_read(fp, NULL, NULL, NULL);
    fclose(fp);
    if (sk == NULL)
        return ENOENT;
    for (i = 0; i < sk_X509_INFO_num(sk); i++) {
        xi = sk_X509_INFO_value(sk, i);
        if (xi->x509 != NULL)
            X509_STORE_add_cert(store, xi->x509);
    }
    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    return 0;
}

static krb5_error_code
load_anchor_dir(X509_STORE *store, const char *path)
{
    DIR *d = NULL;
    struct dirent *dentry = NULL;
    char filename[1024];
    krb5_boolean found_any = FALSE;

    d = opendir(path);
    if (d == NULL)
        return ENOENT;
    while ((dentry = readdir(d)) != NULL) {
        if (dentry->d_name[0] != '.') {
            snprintf(filename, sizeof(filename), "%s/%s",
                     path, dentry->d_name);
            if (load_anchor_file(store, filename) == 0)
                found_any = TRUE;
        }
    }
    closedir(d);
    return found_any ? 0 : ENOENT;
}

static krb5_error_code
load_anchor(SSL_CTX *ctx, const char *location)
{
    X509_STORE *store;
    const char *envloc;

    store = SSL_CTX_get_cert_store(ctx);
    if (strncmp(location, "FILE:", 5) == 0) {
        return load_anchor_file(store, location + 5);
    } else if (strncmp(location, "DIR:", 4) == 0) {
        return load_anchor_dir(store, location + 4);
    } else if (strncmp(location, "ENV:", 4) == 0) {
        envloc = secure_getenv(location + 4);
        if (envloc == NULL)
            return ENOENT;
        return load_anchor(ctx, envloc);
    }
    return EINVAL;
}

static krb5_error_code
load_anchors(krb5_context context, char **anchors, SSL_CTX *sctx)
{
    unsigned int i;
    krb5_error_code ret;

    if (anchors != NULL) {
        for (i = 0; anchors[i] != NULL; i++) {
            ret = load_anchor(sctx, anchors[i]);
            if (ret)
                return ret;
        }
    } else {
        /* Use the library defaults. */
        if (SSL_CTX_set_default_verify_paths(sctx) != 1)
            return ENOENT;
    }

    return 0;
}

static krb5_error_code
setup(krb5_context context, SOCKET fd, const char *servername,
      char **anchors, k5_tls_handle *handle_out)
{
    int e;
    long options = SSL_OP_NO_SSLv2;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    k5_tls_handle handle = NULL;

    *handle_out = NULL;

    (void)CALL_INIT_FUNCTION(init_openssl);
    if (ex_context_id == -1 || ex_handle_id == -1)
        return KRB5_PLUGIN_OP_NOTSUPP;

    /* Do general SSL library setup. */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto error;

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    /*
     * For OpenSSL 3 and later, mark close_notify alerts as optional.  We don't
     * need to worry about truncation attacks because the protocols this module
     * is used with (Kerberos and change-password) receive a single
     * length-delimited message from the server.  For prior versions of OpenSSL
     * we check for SSL_ERROR_SYSCALL when reading instead (this error changes
     * to SSL_ERROR_SSL in OpenSSL 3).
     */
    options |= SSL_OP_IGNORE_UNEXPECTED_EOF;
#endif
    SSL_CTX_set_options(ctx, options);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    X509_STORE_set_flags(SSL_CTX_get_cert_store(ctx), 0);
    e = load_anchors(context, anchors, ctx);
    if (e != 0)
        goto error;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto error;

    if (!SSL_set_fd(ssl, fd))
        goto error;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (!SSL_set_tlsext_host_name(ssl, servername))
        goto error;
#endif
    SSL_set_connect_state(ssl);

    /* Create a handle and allow verify_callback to access it. */
    handle = malloc(sizeof(*handle));
    if (handle == NULL || !SSL_set_ex_data(ssl, ex_handle_id, handle))
        goto error;

    handle->ssl = ssl;
    handle->servername = strdup(servername);
    if (handle->servername == NULL)
        goto error;
    *handle_out = handle;
    SSL_CTX_free(ctx);
    return 0;

error:
    flush_errors(context);
    free(handle);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static k5_tls_status
write_tls(krb5_context context, k5_tls_handle handle, const void *data,
          size_t len)
{
    int nwritten, e;

    /* Try to transmit our request; allow verify_callback to access context. */
    if (!SSL_set_ex_data(handle->ssl, ex_context_id, context))
        return ERROR_TLS;
    nwritten = SSL_write(handle->ssl, data, len);
    (void)SSL_set_ex_data(handle->ssl, ex_context_id, NULL);
    if (nwritten > 0)
        return DONE;

    e = SSL_get_error(handle->ssl, nwritten);
    if (e == SSL_ERROR_WANT_READ)
        return WANT_READ;
    else if (e == SSL_ERROR_WANT_WRITE)
        return WANT_WRITE;
    flush_errors(context);
    return ERROR_TLS;
}

static k5_tls_status
read_tls(krb5_context context, k5_tls_handle handle, void *data,
         size_t data_size, size_t *len_out)
{
    ssize_t nread;
    int e;

    *len_out = 0;

    /* Try to read response data; allow verify_callback to access context. */
    if (!SSL_set_ex_data(handle->ssl, ex_context_id, context))
        return ERROR_TLS;
    nread = SSL_read(handle->ssl, data, data_size);
    (void)SSL_set_ex_data(handle->ssl, ex_context_id, NULL);
    if (nread > 0) {
        *len_out = nread;
        return DATA_READ;
    }

    e = SSL_get_error(handle->ssl, nread);
    if (e == SSL_ERROR_WANT_READ)
        return WANT_READ;
    else if (e == SSL_ERROR_WANT_WRITE)
        return WANT_WRITE;

    if (e == SSL_ERROR_ZERO_RETURN || (e == SSL_ERROR_SYSCALL && nread == 0))
        return DONE;

    flush_errors(context);
    return ERROR_TLS;
}

static void
free_handle(krb5_context context, k5_tls_handle handle)
{
    SSL_free(handle->ssl);
    free(handle->servername);
    free(handle);
}

krb5_error_code
tls_k5tls_initvt(krb5_context context, int maj_ver, int min_ver,
                 krb5_plugin_vtable vtable);

krb5_error_code
tls_k5tls_initvt(krb5_context context, int maj_ver, int min_ver,
                 krb5_plugin_vtable vtable)
{
    k5_tls_vtable vt;

    vt = (k5_tls_vtable)vtable;
    vt->setup = setup;
    vt->write = write_tls;
    vt->read = read_tls;
    vt->free_handle = free_handle;
    return 0;
}

#endif /* TLS_IMPL_OPENSSL */
