/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/sendto_kdc.c */
/*
 * Copyright 1990,1991,2001,2002,2004,2005,2007,2008 by the Massachusetts Institute of Technology.
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
 */
/*
 * MS-KKDCP implementation Copyright 2013,2014 Red Hat, Inc.
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

/* Send packet to KDC for realm; wait for response, retransmitting
 * as necessary. */

#include "k5-int.h"
#include "fake-addrinfo.h"

#include "os-proto.h"

#if defined(HAVE_POLL_H)
#include <poll.h>
#define USE_POLL
#define MAX_POLLFDS 1024
#elif defined(HAVE_SYS_SELECT_H)
#include <sys/select.h>
#endif

#ifndef _WIN32
/* For FIONBIO.  */
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#endif

#ifdef PROXY_TLS_IMPL_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <dirent.h>
#include "checkhost.h"
#endif

#define MAX_PASS                    3
#define DEFAULT_UDP_PREF_LIMIT   1465
#define HARD_UDP_LIMIT          32700 /* could probably do 64K-epsilon ? */

/* Select state flags.  */
#define SSF_READ 0x01
#define SSF_WRITE 0x02
#define SSF_EXCEPTION 0x04

typedef int64_t time_ms;

/* This can be pretty large, so should not be stack-allocated. */
struct select_state {
#ifdef USE_POLL
    struct pollfd fds[MAX_POLLFDS];
#else
    int max;
    fd_set rfds, wfds, xfds;
#endif
    int nfds;
};

/* connection states */
enum conn_states { INITIALIZING, CONNECTING, WRITING, READING, FAILED };
struct incoming_message {
    size_t bufsizebytes_read;
    size_t bufsize;
    size_t pos;
    char *buf;
    unsigned char bufsizebytes[4];
    size_t n_left;
};

struct outgoing_message {
    sg_buf sgbuf[2];
    sg_buf *sgp;
    int sg_count;
    unsigned char msg_len_buf[4];
};

struct conn_state;
typedef krb5_boolean fd_handler_fn(krb5_context context,
                                   const krb5_data *realm,
                                   struct conn_state *conn,
                                   struct select_state *selstate);

struct conn_state {
    SOCKET fd;
    enum conn_states state;
    fd_handler_fn *service_connect;
    fd_handler_fn *service_write;
    fd_handler_fn *service_read;
    struct remote_address addr;
    struct incoming_message in;
    struct outgoing_message out;
    krb5_data callback_buffer;
    size_t server_index;
    struct conn_state *next;
    time_ms endtime;
    krb5_boolean defer;
    struct {
        const char *uri_path;
        const char *servername;
        char *https_request;
#ifdef PROXY_TLS_IMPL_OPENSSL
        SSL *ssl;
#endif
    } http;
};

#ifdef PROXY_TLS_IMPL_OPENSSL
/* Extra-data identifier, used to pass context into the verify callback. */
static int ssl_ex_context_id = -1;
static int ssl_ex_conn_id = -1;
#endif

void
k5_sendto_kdc_initialize(void)
{
#ifdef PROXY_TLS_IMPL_OPENSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ssl_ex_context_id = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    ssl_ex_conn_id = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
#endif
}

/* Get current time in milliseconds. */
static krb5_error_code
get_curtime_ms(time_ms *time_out)
{
    struct timeval tv;

    if (gettimeofday(&tv, 0))
        return errno;
    *time_out = (time_ms)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    return 0;
}

#ifdef PROXY_TLS_IMPL_OPENSSL
static void
free_http_ssl_data(struct conn_state *state)
{
    SSL_free(state->http.ssl);
    state->http.ssl = NULL;
    free(state->http.https_request);
    state->http.https_request = NULL;
}
#else
static void
free_http_ssl_data(struct conn_state *state)
{
}
#endif

#ifdef USE_POLL

/* Find a pollfd in selstate by fd, or abort if we can't find it. */
static inline struct pollfd *
find_pollfd(struct select_state *selstate, int fd)
{
    int i;

    for (i = 0; i < selstate->nfds; i++) {
        if (selstate->fds[i].fd == fd)
            return &selstate->fds[i];
    }
    abort();
}

static void
cm_init_selstate(struct select_state *selstate)
{
    selstate->nfds = 0;
}

static krb5_boolean
cm_add_fd(struct select_state *selstate, int fd)
{
    if (selstate->nfds >= MAX_POLLFDS)
        return FALSE;
    selstate->fds[selstate->nfds].fd = fd;
    selstate->fds[selstate->nfds].events = 0;
    selstate->nfds++;
    return TRUE;
}

static void
cm_remove_fd(struct select_state *selstate, int fd)
{
    struct pollfd *pfd = find_pollfd(selstate, fd);

    *pfd = selstate->fds[selstate->nfds - 1];
    selstate->nfds--;
}

/* Poll for reading (and not writing) on fd the next time we poll. */
static void
cm_read(struct select_state *selstate, int fd)
{
    find_pollfd(selstate, fd)->events = POLLIN;
}

/* Poll for writing (and not reading) on fd the next time we poll. */
static void
cm_write(struct select_state *selstate, int fd)
{
    find_pollfd(selstate, fd)->events = POLLOUT;
}

/* Get the output events for fd in the form of ssflags. */
static unsigned int
cm_get_ssflags(struct select_state *selstate, int fd)
{
    struct pollfd *pfd = find_pollfd(selstate, fd);

    /*
     * OS X sets POLLHUP without POLLOUT on connection error.  Catch this as
     * well as other error events such as POLLNVAL, but only if POLLIN and
     * POLLOUT aren't set, as we can get POLLHUP along with POLLIN with TCP
     * data still to be read.
     */
    if (pfd->revents != 0 && !(pfd->revents & (POLLIN | POLLOUT)))
        return SSF_EXCEPTION;

    return ((pfd->revents & POLLIN) ? SSF_READ : 0) |
        ((pfd->revents & POLLOUT) ? SSF_WRITE : 0) |
        ((pfd->revents & POLLERR) ? SSF_EXCEPTION : 0);
}

#else /* not USE_POLL */

static void
cm_init_selstate(struct select_state *selstate)
{
    selstate->nfds = 0;
    selstate->max = 0;
    FD_ZERO(&selstate->rfds);
    FD_ZERO(&selstate->wfds);
    FD_ZERO(&selstate->xfds);
}

static krb5_boolean
cm_add_fd(struct select_state *selstate, int fd)
{
#ifndef _WIN32  /* On Windows FD_SETSIZE is a count, not a max value. */
    if (fd >= FD_SETSIZE)
        return FALSE;
#endif
    FD_SET(fd, &selstate->xfds);
    if (selstate->max <= fd)
        selstate->max = fd + 1;
    selstate->nfds++;
    return TRUE;
}

static void
cm_remove_fd(struct select_state *selstate, int fd)
{
    FD_CLR(fd, &selstate->rfds);
    FD_CLR(fd, &selstate->wfds);
    FD_CLR(fd, &selstate->xfds);
    if (selstate->max == fd + 1) {
        while (selstate->max > 0 &&
               !FD_ISSET(selstate->max - 1, &selstate->rfds) &&
               !FD_ISSET(selstate->max - 1, &selstate->wfds) &&
               !FD_ISSET(selstate->max - 1, &selstate->xfds))
            selstate->max--;
    }
    selstate->nfds--;
}

/* Select for reading (and not writing) on fd the next time we select. */
static void
cm_read(struct select_state *selstate, int fd)
{
    FD_SET(fd, &selstate->rfds);
    FD_CLR(fd, &selstate->wfds);
}

/* Select for writing (and not reading) on fd the next time we select. */
static void
cm_write(struct select_state *selstate, int fd)
{
    FD_CLR(fd, &selstate->rfds);
    FD_SET(fd, &selstate->wfds);
}

/* Get the events for fd from selstate after a select. */
static unsigned int
cm_get_ssflags(struct select_state *selstate, int fd)
{
    return (FD_ISSET(fd, &selstate->rfds) ? SSF_READ : 0) |
        (FD_ISSET(fd, &selstate->wfds) ? SSF_WRITE : 0) |
        (FD_ISSET(fd, &selstate->xfds) ? SSF_EXCEPTION : 0);
}

#endif /* not USE_POLL */

static krb5_error_code
cm_select_or_poll(const struct select_state *in, time_ms endtime,
                  struct select_state *out, int *sret)
{
#ifndef USE_POLL
    struct timeval tv;
#endif
    krb5_error_code retval;
    time_ms curtime, interval;

    retval = get_curtime_ms(&curtime);
    if (retval != 0)
        return retval;
    interval = (curtime < endtime) ? endtime - curtime : 0;

    /* We don't need a separate copy of the selstate for poll, but use one for
     * consistency with how we use select. */
    *out = *in;

#ifdef USE_POLL
    *sret = poll(out->fds, out->nfds, interval);
#else
    tv.tv_sec = interval / 1000;
    tv.tv_usec = interval % 1000 * 1000;
    *sret = select(out->max, &out->rfds, &out->wfds, &out->xfds, &tv);
#endif

    return (*sret < 0) ? SOCKET_ERRNO : 0;
}

static int
socktype_for_transport(k5_transport transport)
{
    switch (transport) {
    case UDP:
        return SOCK_DGRAM;
    case TCP:
    case HTTPS:
        return SOCK_STREAM;
    default:
        return 0;
    }
}

static int
check_for_svc_unavailable (krb5_context context,
                           const krb5_data *reply,
                           void *msg_handler_data)
{
    krb5_error_code *retval = (krb5_error_code *)msg_handler_data;

    *retval = 0;

    if (krb5_is_krb_error(reply)) {
        krb5_error *err_reply;

        if (decode_krb5_error(reply, &err_reply) == 0) {
            *retval = err_reply->error;
            krb5_free_error(context, err_reply);

            /* Returning 0 means continue to next KDC */
            return (*retval != KDC_ERR_SVC_UNAVAILABLE);
        }
    }

    return 1;
}

/*
 * send the formatted request 'message' to a KDC for realm 'realm' and
 * return the response (if any) in 'reply'.
 *
 * If the message is sent and a response is received, 0 is returned,
 * otherwise an error code is returned.
 *
 * The storage for 'reply' is allocated and should be freed by the caller
 * when finished.
 */

krb5_error_code
krb5_sendto_kdc(krb5_context context, const krb5_data *message,
                const krb5_data *realm, krb5_data *reply, int *use_master,
                int no_udp)
{
    krb5_error_code retval, err;
    struct serverlist servers;
    int server_used;
    k5_transport_strategy strategy;

    /*
     * find KDC location(s) for realm
     */

    /*
     * BUG: This code won't return "interesting" errors (e.g., out of mem,
     * bad config file) from locate_kdc.  KRB5_REALM_CANT_RESOLVE can be
     * ignored from one query of two, but if only one query is done, or
     * both return that error, it should be returned to the caller.  Also,
     * "interesting" errors (not KRB5_KDC_UNREACH) from sendto_{udp,tcp}
     * should probably be returned as well.
     */

    TRACE_SENDTO_KDC(context, message->length, realm, *use_master, no_udp);

    if (!no_udp && context->udp_pref_limit < 0) {
        int tmp;
        retval = profile_get_integer(context->profile,
                                     KRB5_CONF_LIBDEFAULTS, KRB5_CONF_UDP_PREFERENCE_LIMIT, 0,
                                     DEFAULT_UDP_PREF_LIMIT, &tmp);
        if (retval)
            return retval;
        if (tmp < 0)
            tmp = DEFAULT_UDP_PREF_LIMIT;
        else if (tmp > HARD_UDP_LIMIT)
            /* In the unlikely case that a *really* big value is
               given, let 'em use as big as we think we can
               support.  */
            tmp = HARD_UDP_LIMIT;
        context->udp_pref_limit = tmp;
    }

    if (no_udp)
        strategy = NO_UDP;
    else if (message->length <= (unsigned int) context->udp_pref_limit)
        strategy = UDP_FIRST;
    else
        strategy = UDP_LAST;

    retval = k5_locate_kdc(context, realm, &servers, *use_master, no_udp);
    if (retval)
        return retval;

    err = 0;
    retval = k5_sendto(context, message, realm, &servers, strategy, NULL,
                       reply, NULL, NULL, &server_used,
                       check_for_svc_unavailable, &err);
    if (retval == KRB5_KDC_UNREACH) {
        if (err == KDC_ERR_SVC_UNAVAILABLE) {
            retval = KRB5KDC_ERR_SVC_UNAVAILABLE;
        } else {
            k5_setmsg(context, retval,
                      _("Cannot contact any KDC for realm '%.*s'"),
                      realm->length, realm->data);
        }
    }
    if (retval)
        goto cleanup;

    /* Set use_master to 1 if we ended up talking to a master when we didn't
     * explicitly request to. */
    if (*use_master == 0) {
        *use_master = k5_kdc_is_master(context, realm,
                                       &servers.servers[server_used]);
        TRACE_SENDTO_KDC_MASTER(context, *use_master);
    }

cleanup:
    k5_free_serverlist(&servers);
    return retval;
}

/*
 * Notes:
 *
 * Getting "connection refused" on a connected UDP socket causes
 * select to indicate write capability on UNIX, but only shows up
 * as an exception on Windows.  (I don't think any UNIX system flags
 * the error as an exception.)  So we check for both, or make it
 * system-specific.
 *
 * Always watch for responses from *any* of the servers.  Eventually
 * fix the UDP code to do the same.
 *
 * To do:
 * - TCP NOPUSH/CORK socket options?
 * - error codes that don't suck
 * - getsockopt(SO_ERROR) to check connect status
 * - handle error RESPONSE_TOO_BIG from UDP server and use TCP
 *   connections already in progress
 */

static fd_handler_fn service_tcp_connect;
static fd_handler_fn service_tcp_write;
static fd_handler_fn service_tcp_read;
static fd_handler_fn service_udp_read;
static fd_handler_fn service_https_write;
static fd_handler_fn service_https_read;

#ifdef PROXY_TLS_IMPL_OPENSSL
static krb5_error_code
make_proxy_request(struct conn_state *state, const krb5_data *realm,
                   const krb5_data *message, char **req_out, size_t *len_out)
{
    krb5_kkdcp_message pm;
    krb5_data *encoded_pm = NULL;
    struct k5buf buf;
    const char *uri_path;
    krb5_error_code ret;

    *req_out = NULL;
    *len_out = 0;

    /*
     * Stuff the message length in at the front of the kerb_message field
     * before encoding.  The proxied messages are actually the payload we'd
     * be sending and receiving if we were using plain TCP.
     */
    memset(&pm, 0, sizeof(pm));
    ret = alloc_data(&pm.kerb_message, message->length + 4);
    if (ret != 0)
        goto cleanup;
    store_32_be(message->length, pm.kerb_message.data);
    memcpy(pm.kerb_message.data + 4, message->data, message->length);
    pm.target_domain = *realm;
    ret = encode_krb5_kkdcp_message(&pm, &encoded_pm);
    if (ret != 0)
        goto cleanup;

    /* Build the request to transmit: the headers + the proxy message. */
    k5_buf_init_dynamic(&buf);
    uri_path = (state->http.uri_path != NULL) ? state->http.uri_path : "";
    k5_buf_add_fmt(&buf, "POST /%s HTTP/1.0\r\n", uri_path);
    k5_buf_add(&buf, "Cache-Control: no-cache\r\n");
    k5_buf_add(&buf, "Pragma: no-cache\r\n");
    k5_buf_add(&buf, "User-Agent: kerberos/1.0\r\n");
    k5_buf_add(&buf, "Content-type: application/kerberos\r\n");
    k5_buf_add_fmt(&buf, "Content-Length: %d\r\n\r\n", encoded_pm->length);
    k5_buf_add_len(&buf, encoded_pm->data, encoded_pm->length);
    if (k5_buf_data(&buf) == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }

    *req_out = k5_buf_data(&buf);
    *len_out = k5_buf_len(&buf);

cleanup:
    krb5_free_data_contents(NULL, &pm.kerb_message);
    krb5_free_data(NULL, encoded_pm);
    return ret;
}
#else
static krb5_error_code
make_proxy_request(struct conn_state *state, const krb5_data *realm,
                   const krb5_data *message, char **req_out, size_t *len_out)
{
    abort();
}
#endif

/* Set up the actual message we will send across the underlying transport to
 * communicate the payload message, using one or both of state->out.sgbuf. */
static krb5_error_code
set_transport_message(struct conn_state *state, const krb5_data *realm,
                      const krb5_data *message)
{
    struct outgoing_message *out = &state->out;
    char *req = NULL;
    size_t reqlen;
    krb5_error_code ret;

    if (message == NULL || message->length == 0)
        return 0;

    if (state->addr.transport == TCP) {
        store_32_be(message->length, out->msg_len_buf);
        SG_SET(&out->sgbuf[0], out->msg_len_buf, 4);
        SG_SET(&out->sgbuf[1], message->data, message->length);
        out->sg_count = 2;
        return 0;
    } else if (state->addr.transport == HTTPS) {
        ret = make_proxy_request(state, realm, message, &req, &reqlen);
        if (ret != 0)
            return ret;
        SG_SET(&state->out.sgbuf[0], req, reqlen);
        SG_SET(&state->out.sgbuf[1], 0, 0);
        state->out.sg_count = 1;
        free(state->http.https_request);
        state->http.https_request = req;
        return 0;
    } else {
        SG_SET(&out->sgbuf[0], message->data, message->length);
        SG_SET(&out->sgbuf[1], NULL, 0);
        out->sg_count = 1;
        return 0;
    }
}

static krb5_error_code
add_connection(struct conn_state **conns, k5_transport transport,
               krb5_boolean defer, struct addrinfo *ai, size_t server_index,
               const krb5_data *realm, const char *hostname,
               const char *uri_path, char **udpbufp)
{
    struct conn_state *state, **tailptr;

    state = calloc(1, sizeof(*state));
    if (state == NULL)
        return ENOMEM;
    state->state = INITIALIZING;
    state->out.sgp = state->out.sgbuf;
    state->addr.transport = transport;
    state->addr.family = ai->ai_family;
    state->addr.len = ai->ai_addrlen;
    memcpy(&state->addr.saddr, ai->ai_addr, ai->ai_addrlen);
    state->defer = defer;
    state->fd = INVALID_SOCKET;
    state->server_index = server_index;
    SG_SET(&state->out.sgbuf[1], NULL, 0);
    if (transport == TCP) {
        state->service_connect = service_tcp_connect;
        state->service_write = service_tcp_write;
        state->service_read = service_tcp_read;
    } else if (transport == HTTPS) {
        state->service_connect = service_tcp_connect;
        state->service_write = service_https_write;
        state->service_read = service_https_read;
        state->http.uri_path = uri_path;
        state->http.servername = hostname;
    } else {
        state->service_connect = NULL;
        state->service_write = NULL;
        state->service_read = service_udp_read;

        if (*udpbufp == NULL) {
            *udpbufp = malloc(MAX_DGRAM_SIZE);
            if (*udpbufp == 0)
                return ENOMEM;
        }
        state->in.buf = *udpbufp;
        state->in.bufsize = MAX_DGRAM_SIZE;
    }

    /* Chain the new state onto the tail of the list. */
    for (tailptr = conns; *tailptr != NULL; tailptr = &(*tailptr)->next);
    *tailptr = state;

    return 0;
}

static int
translate_ai_error (int err)
{
    switch (err) {
    case 0:
        return 0;
    case EAI_BADFLAGS:
    case EAI_FAMILY:
    case EAI_SOCKTYPE:
    case EAI_SERVICE:
        /* All of these indicate bad inputs to getaddrinfo.  */
        return EINVAL;
    case EAI_AGAIN:
        /* Translate to standard errno code.  */
        return EAGAIN;
    case EAI_MEMORY:
        /* Translate to standard errno code.  */
        return ENOMEM;
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
#endif
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
    case EAI_NODATA:
#endif
    case EAI_NONAME:
        /* Name not known or no address data, but no error.  Do
           nothing more.  */
        return 0;
#ifdef EAI_OVERFLOW
    case EAI_OVERFLOW:
        /* An argument buffer overflowed.  */
        return EINVAL;          /* XXX */
#endif
#ifdef EAI_SYSTEM
    case EAI_SYSTEM:
        /* System error, obviously.  */
        return errno;
#endif
    default:
        /* An error code we haven't handled?  */
        return EINVAL;
    }
}

/*
 * Resolve the entry in servers with index ind, adding connections to the list
 * *conns.  Connections are added for each of socktype1 and (if not zero)
 * socktype2.  message and udpbufp are used to initialize the connections; see
 * add_connection above.  If no addresses are available for an entry but no
 * internal name resolution failure occurs, return 0 without adding any new
 * connections.
 */
static krb5_error_code
resolve_server(krb5_context context, const krb5_data *realm,
               const struct serverlist *servers, size_t ind,
               k5_transport_strategy strategy, const krb5_data *message,
               char **udpbufp, struct conn_state **conns)
{
    krb5_error_code retval;
    struct server_entry *entry = &servers->servers[ind];
    k5_transport transport;
    struct addrinfo *addrs, *a, hint, ai;
    krb5_boolean defer;
    int err, result;
    char portbuf[64];

    /* Skip UDP entries if we don't want UDP. */
    if (strategy == NO_UDP && entry->transport == UDP)
        return 0;

    transport = (strategy == UDP_FIRST) ? UDP : TCP;
    if (entry->hostname == NULL) {
        /* Added by a module, so transport is either TCP or UDP. */
        ai.ai_socktype = socktype_for_transport(entry->transport);
        ai.ai_family = entry->family;
        ai.ai_addrlen = entry->addrlen;
        ai.ai_addr = (struct sockaddr *)&entry->addr;
        defer = (entry->transport != transport);
        return add_connection(conns, entry->transport, defer, &ai, ind, realm,
                              NULL, entry->uri_path, udpbufp);
    }

    /* If the entry has a specified transport, use it. */
    if (entry->transport != TCP_OR_UDP)
        transport = entry->transport;

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = entry->family;
    hint.ai_socktype = socktype_for_transport(transport);
    hint.ai_flags = AI_ADDRCONFIG;
#ifdef AI_NUMERICSERV
    hint.ai_flags |= AI_NUMERICSERV;
#endif
    result = snprintf(portbuf, sizeof(portbuf), "%d", ntohs(entry->port));
    if (SNPRINTF_OVERFLOW(result, sizeof(portbuf)))
        return EINVAL;
    TRACE_SENDTO_KDC_RESOLVING(context, entry->hostname);
    err = getaddrinfo(entry->hostname, portbuf, &hint, &addrs);
    if (err)
        return translate_ai_error(err);

    /* Add each address with the specified or preferred transport. */
    retval = 0;
    for (a = addrs; a != 0 && retval == 0; a = a->ai_next) {
        retval = add_connection(conns, transport, FALSE, a, ind, realm,
                                entry->hostname, entry->uri_path, udpbufp);
    }

    /* For TCP_OR_UDP entries, add each address again with the non-preferred
     * transport, unless we are avoiding UDP.  Flag these as deferred. */
    if (retval == 0 && entry->transport == TCP_OR_UDP && strategy != NO_UDP) {
        transport = (strategy == UDP_FIRST) ? TCP : UDP;
        for (a = addrs; a != 0 && retval == 0; a = a->ai_next) {
            a->ai_socktype = socktype_for_transport(transport);
            retval = add_connection(conns, transport, TRUE, a, ind, realm,
                                    entry->hostname, entry->uri_path, udpbufp);
        }
    }
    freeaddrinfo(addrs);
    return retval;
}

static int
start_connection(krb5_context context, struct conn_state *state,
                 const krb5_data *message, struct select_state *selstate,
                 const krb5_data *realm,
                 struct sendto_callback_info *callback_info)
{
    int fd, e, type;
    static const int one = 1;
    static const struct linger lopt = { 0, 0 };

    type = socktype_for_transport(state->addr.transport);
    fd = socket(state->addr.family, type, 0);
    if (fd == INVALID_SOCKET)
        return -1;              /* try other hosts */
    set_cloexec_fd(fd);
    /* Make it non-blocking.  */
    ioctlsocket(fd, FIONBIO, (const void *) &one);
    if (state->addr.transport == TCP) {
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt));
        TRACE_SENDTO_KDC_TCP_CONNECT(context, &state->addr);
    }

    /* Start connecting to KDC.  */
    e = connect(fd, (struct sockaddr *)&state->addr.saddr, state->addr.len);
    if (e != 0) {
        /*
         * This is the path that should be followed for non-blocking
         * connections.
         */
        if (SOCKET_ERRNO == EINPROGRESS || SOCKET_ERRNO == EWOULDBLOCK) {
            state->state = CONNECTING;
            state->fd = fd;
        } else {
            (void) closesocket(fd);
            state->state = FAILED;
            return -2;
        }
    } else {
        /*
         * Connect returned zero even though we made it non-blocking.  This
         * happens normally for UDP sockets, and can perhaps also happen for
         * TCP sockets connecting to localhost.
         */
        state->state = WRITING;
        state->fd = fd;
    }

    /*
     * Here's where KPASSWD callback gets the socket information it needs for
     * a kpasswd request
     */
    if (callback_info) {

        e = callback_info->pfn_callback(state->fd, callback_info->data,
                                        &state->callback_buffer);
        if (e != 0) {
            (void) closesocket(fd);
            state->fd = INVALID_SOCKET;
            state->state = FAILED;
            return -3;
        }

        message = &state->callback_buffer;
    }

    e = set_transport_message(state, realm, message);
    if (e != 0) {
        TRACE_SENDTO_KDC_ERROR_SET_MESSAGE(context, &state->addr, e);
        (void) closesocket(state->fd);
        state->fd = INVALID_SOCKET;
        state->state = FAILED;
        return -4;
    }

    if (state->addr.transport == UDP) {
        /* Send it now.  */
        ssize_t ret;
        sg_buf *sg = &state->out.sgbuf[0];

        TRACE_SENDTO_KDC_UDP_SEND_INITIAL(context, &state->addr);
        ret = send(state->fd, SG_BUF(sg), SG_LEN(sg), 0);
        if (ret < 0 || (size_t) ret != SG_LEN(sg)) {
            TRACE_SENDTO_KDC_UDP_ERROR_SEND_INITIAL(context, &state->addr,
                                                    SOCKET_ERRNO);
            (void) closesocket(state->fd);
            state->fd = INVALID_SOCKET;
            state->state = FAILED;
            return -5;
        } else {
            state->state = READING;
        }
    }

    if (!cm_add_fd(selstate, state->fd)) {
        (void) closesocket(state->fd);
        state->fd = INVALID_SOCKET;
        state->state = FAILED;
        return -1;
    }
    if (state->state == CONNECTING || state->state == WRITING)
        cm_write(selstate, state->fd);
    else
        cm_read(selstate, state->fd);

    return 0;
}

/* Return 0 if we sent something, non-0 otherwise.
   If 0 is returned, the caller should delay waiting for a response.
   Otherwise, the caller should immediately move on to process the
   next connection.  */
static int
maybe_send(krb5_context context, struct conn_state *conn,
           const krb5_data *message, struct select_state *selstate,
           const krb5_data *realm,
           struct sendto_callback_info *callback_info)
{
    sg_buf *sg;
    ssize_t ret;

    if (conn->state == INITIALIZING) {
        return start_connection(context, conn, message, selstate,
                                realm, callback_info);
    }

    /* Did we already shut down this channel?  */
    if (conn->state == FAILED) {
        return -1;
    }

    if (conn->addr.transport != UDP) {
        /* The select callback will handle flushing any data we
           haven't written yet, and we only write it once.  */
        return -1;
    }

    /* UDP - retransmit after a previous attempt timed out. */
    sg = &conn->out.sgbuf[0];
    TRACE_SENDTO_KDC_UDP_SEND_RETRY(context, &conn->addr);
    ret = send(conn->fd, SG_BUF(sg), SG_LEN(sg), 0);
    if (ret < 0 || (size_t) ret != SG_LEN(sg)) {
        TRACE_SENDTO_KDC_UDP_ERROR_SEND_RETRY(context, &conn->addr,
                                              SOCKET_ERRNO);
        /* Keep connection alive, we'll try again next pass.

           Is this likely to catch any errors we didn't get from the
           select callbacks?  */
        return -1;
    }
    /* Yay, it worked.  */
    return 0;
}

static void
kill_conn(krb5_context context, struct conn_state *conn,
          struct select_state *selstate)
{
    free_http_ssl_data(conn);

    if (socktype_for_transport(conn->addr.transport) == SOCK_STREAM)
        TRACE_SENDTO_KDC_TCP_DISCONNECT(context, &conn->addr);
    cm_remove_fd(selstate, conn->fd);

    closesocket(conn->fd);
    conn->fd = INVALID_SOCKET;
    conn->state = FAILED;
}

/* Check socket for error.  */
static int
get_so_error(int fd)
{
    int e, sockerr;
    socklen_t sockerrlen;

    sockerr = 0;
    sockerrlen = sizeof(sockerr);
    e = getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &sockerrlen);
    if (e != 0) {
        /* What to do now?  */
        e = SOCKET_ERRNO;
        return e;
    }
    return sockerr;
}

/* Perform next step in sending.  Return true on usable data. */
static krb5_boolean
service_dispatch(krb5_context context, const krb5_data *realm,
                 struct conn_state *conn, struct select_state *selstate,
                 int ssflags)
{
    /* Check for a socket exception. */
    if (ssflags & SSF_EXCEPTION) {
        kill_conn(context, conn, selstate);
        return FALSE;
    }

    switch (conn->state) {
    case CONNECTING:
        assert(conn->service_connect != NULL);
        return conn->service_connect(context, realm, conn, selstate);
    case WRITING:
        assert(conn->service_write != NULL);
        return conn->service_write(context, realm, conn, selstate);
    case READING:
        assert(conn->service_read != NULL);
        return conn->service_read(context, realm, conn, selstate);
    default:
        abort();
    }
}

/* Initialize TCP transport. */
static krb5_boolean
service_tcp_connect(krb5_context context, const krb5_data *realm,
                    struct conn_state *conn, struct select_state *selstate)
{
    /* Check whether the connection succeeded. */
    int e = get_so_error(conn->fd);

    if (e) {
        TRACE_SENDTO_KDC_TCP_ERROR_CONNECT(context, &conn->addr, e);
        kill_conn(context, conn, selstate);
        return FALSE;
    }

    conn->state = WRITING;

    /* Record this connection's timeout for service_fds. */
    if (get_curtime_ms(&conn->endtime) == 0)
        conn->endtime += 10000;

    return conn->service_write(context, realm, conn, selstate);
}

/* Sets conn->state to READING when done. */
static krb5_boolean
service_tcp_write(krb5_context context, const krb5_data *realm,
                  struct conn_state *conn, struct select_state *selstate)
{
    ssize_t nwritten;
    SOCKET_WRITEV_TEMP tmp;

    TRACE_SENDTO_KDC_TCP_SEND(context, &conn->addr);
    nwritten = SOCKET_WRITEV(conn->fd, conn->out.sgp, conn->out.sg_count, tmp);
    if (nwritten < 0) {
        TRACE_SENDTO_KDC_TCP_ERROR_SEND(context, &conn->addr, SOCKET_ERRNO);
        kill_conn(context, conn, selstate);
        return FALSE;
    }
    while (nwritten) {
        sg_buf *sgp = conn->out.sgp;
        if ((size_t)nwritten < SG_LEN(sgp)) {
            SG_ADVANCE(sgp, (size_t)nwritten);
            nwritten = 0;
        } else {
            nwritten -= SG_LEN(sgp);
            conn->out.sgp++;
            conn->out.sg_count--;
        }
    }
    if (conn->out.sg_count == 0) {
        /* Done writing, switch to reading. */
        cm_read(selstate, conn->fd);
        conn->state = READING;
    }
    return FALSE;
}

/* Return true on usable data. */
static krb5_boolean
service_tcp_read(krb5_context context, const krb5_data *realm,
                 struct conn_state *conn, struct select_state *selstate)
{
    ssize_t nread;
    int e = 0;
    struct incoming_message *in = &conn->in;

    if (in->bufsizebytes_read == 4) {
        /* Reading data.  */
        nread = SOCKET_READ(conn->fd, &in->buf[in->pos], in->n_left);
        if (nread <= 0) {
            e = nread ? SOCKET_ERRNO : ECONNRESET;
            TRACE_SENDTO_KDC_TCP_ERROR_RECV(context, &conn->addr, e);
            kill_conn(context, conn, selstate);
            return FALSE;
        }
        in->n_left -= nread;
        in->pos += nread;
        if (in->n_left <= 0)
            return TRUE;
    } else {
        /* Reading length.  */
        nread = SOCKET_READ(conn->fd, in->bufsizebytes + in->bufsizebytes_read,
                            4 - in->bufsizebytes_read);
        if (nread <= 0) {
            e = nread ? SOCKET_ERRNO : ECONNRESET;
            TRACE_SENDTO_KDC_TCP_ERROR_RECV_LEN(context, &conn->addr, e);
            kill_conn(context, conn, selstate);
            return FALSE;
        }
        in->bufsizebytes_read += nread;
        if (in->bufsizebytes_read == 4) {
            unsigned long len = load_32_be(in->bufsizebytes);
            /* Arbitrary 1M cap.  */
            if (len > 1 * 1024 * 1024) {
                kill_conn(context, conn, selstate);
                return FALSE;
            }
            in->bufsize = in->n_left = len;
            in->pos = 0;
            in->buf = malloc(len);
            if (in->buf == NULL) {
                kill_conn(context, conn, selstate);
                return FALSE;
            }
        }
    }
    return FALSE;
}

/* Process events on a UDP socket.  Return true if we get a reply. */
static krb5_boolean
service_udp_read(krb5_context context, const krb5_data *realm,
                 struct conn_state *conn, struct select_state *selstate)
{
    int nread;

    nread = recv(conn->fd, conn->in.buf, conn->in.bufsize, 0);
    if (nread < 0) {
        TRACE_SENDTO_KDC_UDP_ERROR_RECV(context, &conn->addr, SOCKET_ERRNO);
        kill_conn(context, conn, selstate);
        return FALSE;
    }
    conn->in.pos = nread;
    return TRUE;
}

#ifdef PROXY_TLS_IMPL_OPENSSL
/* Output any error strings that OpenSSL's accumulated as tracing messages. */
static void
flush_ssl_errors(krb5_context context)
{
    unsigned long err;
    char buf[128];

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        TRACE_SENDTO_KDC_HTTPS_ERROR(context, buf);
    }
}

static krb5_error_code
load_http_anchor_file(X509_STORE *store, const char *path)
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
load_http_anchor_dir(X509_STORE *store, const char *path)
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
            if (load_http_anchor_file(store, filename) == 0)
                found_any = TRUE;
        }
    }
    closedir(d);
    return found_any ? 0 : ENOENT;
}

static krb5_error_code
load_http_anchor(SSL_CTX *ctx, const char *location)
{
    X509_STORE *store;
    const char *envloc;

    store = SSL_CTX_get_cert_store(ctx);
    if (strncmp(location, "FILE:", 5) == 0) {
        return load_http_anchor_file(store, location + 5);
    } else if (strncmp(location, "DIR:", 4) == 0) {
        return load_http_anchor_dir(store, location + 4);
    } else if (strncmp(location, "ENV:", 4) == 0) {
        envloc = getenv(location + 4);
        if (envloc == NULL)
            return ENOENT;
        return load_http_anchor(ctx, envloc);
    }
    return EINVAL;
}

static krb5_error_code
load_http_verify_anchors(krb5_context context, const krb5_data *realm,
                         SSL_CTX *sctx)
{
    const char *anchors[4];
    char **values = NULL, *realmz;
    unsigned int i;
    krb5_error_code err;

    realmz = k5memdup0(realm->data, realm->length, &err);
    if (realmz == NULL)
        goto cleanup;

    /* Load the configured anchors. */
    anchors[0] = KRB5_CONF_REALMS;
    anchors[1] = realmz;
    anchors[2] = KRB5_CONF_HTTP_ANCHORS;
    anchors[3] = NULL;
    if (profile_get_values(context->profile, anchors, &values) == 0) {
        for (i = 0; values[i] != NULL; i++) {
            err = load_http_anchor(sctx, values[i]);
            if (err != 0)
                break;
        }
        profile_free_list(values);
    } else {
        /* Use the library defaults. */
        if (SSL_CTX_set_default_verify_paths(sctx) != 1)
            err = ENOENT;
    }

cleanup:
    free(realmz);
    return err;
}

static krb5_boolean
ssl_check_name_or_ip(X509 *x, const char *expected_name)
{
    struct in_addr in;
    struct in6_addr in6;

    if (inet_aton(expected_name, &in) != 0 ||
        inet_pton(AF_INET6, expected_name, &in6) != 0) {
        return k5_check_cert_address(x, expected_name);
    } else {
        return k5_check_cert_servername(x, expected_name);
    }
}

static int
ssl_verify_callback(int preverify_ok, X509_STORE_CTX *store_ctx)
{
    X509 *x;
    SSL *ssl;
    BIO *bio;
    krb5_context context;
    int err, depth;
    struct conn_state *conn = NULL;
    const char *cert = NULL, *errstr, *expected_name;
    size_t count;

    ssl = X509_STORE_CTX_get_ex_data(store_ctx,
                                     SSL_get_ex_data_X509_STORE_CTX_idx());
    context = SSL_get_ex_data(ssl, ssl_ex_context_id);
    conn = SSL_get_ex_data(ssl, ssl_ex_conn_id);
    /* We do have the peer's cert, right? */
    x = X509_STORE_CTX_get_current_cert(store_ctx);
    if (x == NULL) {
        TRACE_SENDTO_KDC_HTTPS_NO_REMOTE_CERTIFICATE(context);
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
            X509_NAME_print_ex(bio, x->cert_info->subject, 0, 0);
            count = BIO_get_mem_data(bio, &cert);
            errstr = X509_verify_cert_error_string(err);
            TRACE_SENDTO_KDC_HTTPS_PROXY_CERTIFICATE_ERROR(context, depth,
                                                           count, cert, err,
                                                           errstr);
            BIO_free(bio);
        }
        return 0;
    }
    /* If we're not looking at the peer, we're done and everything's ok. */
    if (depth != 0)
        return 1;
    /* Check if the name we expect to find is in the certificate. */
    expected_name = conn->http.servername;
    if (ssl_check_name_or_ip(x, expected_name)) {
        TRACE_SENDTO_KDC_HTTPS_SERVER_NAME_MATCH(context, expected_name);
        return 1;
    } else {
        TRACE_SENDTO_KDC_HTTPS_SERVER_NAME_MISMATCH(context, expected_name);
    }
    /* The name didn't match. */
    return 0;
}

/*
 * Set up structures that we use to manage the SSL handling for this connection
 * and apply any non-default settings.  Kill the connection and return false if
 * anything goes wrong while we're doing that; return true otherwise.
 */
static krb5_boolean
setup_ssl(krb5_context context, const krb5_data *realm,
          struct conn_state *conn, struct select_state *selstate)
{
    int e;
    long options;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    if (ssl_ex_context_id == -1 || ssl_ex_conn_id == -1)
        goto kill_conn;

    /* Do general SSL library setup. */
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
        goto kill_conn;
    options = SSL_CTX_get_options(ctx);
    SSL_CTX_set_options(ctx, options | SSL_OP_NO_SSLv2);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ssl_verify_callback);
    X509_STORE_set_flags(SSL_CTX_get_cert_store(ctx), 0);
    e = load_http_verify_anchors(context, realm, ctx);
    if (e != 0)
        goto kill_conn;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto kill_conn;

    if (!SSL_set_ex_data(ssl, ssl_ex_context_id, context))
        goto kill_conn;
    if (!SSL_set_ex_data(ssl, ssl_ex_conn_id, conn))
        goto kill_conn;

    /* Tell the SSL library about the socket. */
    if (!SSL_set_fd(ssl, conn->fd))
        goto kill_conn;
    SSL_set_connect_state(ssl);

    SSL_CTX_free(ctx);
    conn->http.ssl = ssl;

    return TRUE;

kill_conn:
    TRACE_SENDTO_KDC_HTTPS_ERROR_CONNECT(context, &conn->addr);
    flush_ssl_errors(context);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    kill_conn(context, conn, selstate);
    return FALSE;
}

/* Set conn->state to READING when done; otherwise, call a cm_set_. */
static krb5_boolean
service_https_write(krb5_context context, const krb5_data *realm,
                    struct conn_state *conn, struct select_state *selstate)
{
    ssize_t nwritten;
    int e;

    /* If this is our first time in here, set up the SSL context. */
    if (conn->http.ssl == NULL && !setup_ssl(context, realm, conn, selstate))
        return FALSE;

    /* Try to transmit our request to the server. */
    nwritten = SSL_write(conn->http.ssl, SG_BUF(conn->out.sgp),
                         SG_LEN(conn->out.sgbuf));
    if (nwritten <= 0) {
        e = SSL_get_error(conn->http.ssl, nwritten);
        if (e == SSL_ERROR_WANT_READ) {
            cm_read(selstate, conn->fd);
            return FALSE;
        } else if (e == SSL_ERROR_WANT_WRITE) {
            cm_write(selstate, conn->fd);
            return FALSE;
        }
        TRACE_SENDTO_KDC_HTTPS_ERROR_SEND(context, &conn->addr);
        flush_ssl_errors(context);
        kill_conn(context, conn, selstate);
        return FALSE;
    }

    /* Done writing, switch to reading. */
    TRACE_SENDTO_KDC_HTTPS_SEND(context, &conn->addr);
    cm_read(selstate, conn->fd);
    conn->state = READING;
    return FALSE;
}

/*
 * Return true on readable data, call a cm_read/write function and return
 * false if the SSL layer needs it, kill the connection otherwise.
 */
static krb5_boolean
https_read_bytes(krb5_context context, struct conn_state *conn,
                 struct select_state *selstate)
{
    size_t bufsize;
    ssize_t nread;
    krb5_boolean readbytes = FALSE;
    int e = 0;
    char *tmp;
    struct incoming_message *in = &conn->in;

    for (;;) {
        if (in->buf == NULL || in->bufsize - in->pos < 1024) {
            bufsize = in->bufsize ? in->bufsize * 2 : 8192;
            if (bufsize > 1024 * 1024) {
                kill_conn(context, conn, selstate);
                return FALSE;
            }
            tmp = realloc(in->buf, bufsize);
            if (tmp == NULL) {
                kill_conn(context, conn, selstate);
                return FALSE;
            }
            in->buf = tmp;
            in->bufsize = bufsize;
        }

        nread = SSL_read(conn->http.ssl, &in->buf[in->pos],
                         in->bufsize - in->pos - 1);
        if (nread <= 0)
            break;
        in->pos += nread;
        in->buf[in->pos] = '\0';
        readbytes = TRUE;
    }

    e = SSL_get_error(conn->http.ssl, nread);
    if (e == SSL_ERROR_WANT_READ) {
        cm_read(selstate, conn->fd);
        return FALSE;
    } else if (e == SSL_ERROR_WANT_WRITE) {
        cm_write(selstate, conn->fd);
        return FALSE;
    } else if ((e == SSL_ERROR_ZERO_RETURN) ||
               (e == SSL_ERROR_SYSCALL && nread == 0 && readbytes)) {
        return TRUE;
    }

    e = readbytes ? SOCKET_ERRNO : ECONNRESET;
    TRACE_SENDTO_KDC_HTTPS_ERROR_RECV(context, &conn->addr, e);
    flush_ssl_errors(context);
    kill_conn(context, conn, selstate);
    return FALSE;
}

/* Return true on readable, valid KKDCPP data. */
static krb5_boolean
service_https_read(krb5_context context, const krb5_data *realm,
                   struct conn_state *conn, struct select_state *selstate)
{
    krb5_kkdcp_message *pm = NULL;
    krb5_data buf;
    const char *rep;
    struct incoming_message *in = &conn->in;

    /* Read data through the encryption layer. */
    if (!https_read_bytes(context, conn, selstate))
        return FALSE;

    /* Find the beginning of the response body. */
    rep = strstr(in->buf, "\r\n\r\n");
    if (rep == NULL)
        goto kill_conn;
    rep += 4;

    /* Decode the response. */
    buf = make_data((char *)rep, in->pos - (rep - in->buf));
    if (decode_krb5_kkdcp_message(&buf, &pm) != 0)
        goto kill_conn;

    /* Check and discard the message length at the front of the kerb_message
     * field after decoding.  If it's wrong or missing, something broke. */
    if (pm->kerb_message.length < 4 ||
        load_32_be(pm->kerb_message.data) != pm->kerb_message.length - 4) {
        goto kill_conn;
    }

    /* Replace all of the content that we read back with just the message. */
    memcpy(in->buf, pm->kerb_message.data + 4, pm->kerb_message.length - 4);
    in->pos = pm->kerb_message.length - 4;
    k5_free_kkdcp_message(context, pm);

    return TRUE;

kill_conn:
    TRACE_SENDTO_KDC_HTTPS_ERROR(context, in->buf);
    k5_free_kkdcp_message(context, pm);
    kill_conn(context, conn, selstate);
    return FALSE;
}
#else
static krb5_boolean
service_https_write(krb5_context context, const krb5_data *realm,
                    struct conn_state *conn, struct select_state *selstate)
{
    abort();
}
static krb5_boolean
service_https_read(krb5_context context, const krb5_data *realm,
                   struct conn_state *conn, struct select_state *selstate)
{
    abort();
}
#endif

/* Return the maximum of endtime and the endtime fields of all currently active
 * TCP connections. */
static time_ms
get_endtime(time_ms endtime, struct conn_state *conns)
{
    struct conn_state *state;

    for (state = conns; state != NULL; state = state->next) {
        if (state->addr.transport == TCP &&
            (state->state == READING || state->state == WRITING) &&
            state->endtime > endtime)
            endtime = state->endtime;
    }
    return endtime;
}

static krb5_boolean
service_fds(krb5_context context, struct select_state *selstate,
            time_ms interval, struct conn_state *conns,
            struct select_state *seltemp, const krb5_data *realm,
            int (*msg_handler)(krb5_context, const krb5_data *, void *),
            void *msg_handler_data, struct conn_state **winner_out)
{
    int e, selret = 0;
    time_ms endtime;
    struct conn_state *state;

    *winner_out = NULL;

    e = get_curtime_ms(&endtime);
    if (e)
        return TRUE;
    endtime += interval;

    e = 0;
    while (selstate->nfds > 0) {
        e = cm_select_or_poll(selstate, get_endtime(endtime, conns),
                              seltemp, &selret);
        if (e == EINTR)
            continue;
        if (e != 0)
            break;

        if (selret == 0)
            /* Timeout, return to caller.  */
            return FALSE;

        /* Got something on a socket, process it.  */
        for (state = conns; state != NULL; state = state->next) {
            int ssflags;

            if (state->fd == INVALID_SOCKET)
                continue;
            ssflags = cm_get_ssflags(seltemp, state->fd);
            if (!ssflags)
                continue;

            if (service_dispatch(context, realm, state, selstate, ssflags)) {
                int stop = 1;

                if (msg_handler != NULL) {
                    krb5_data reply = make_data(state->in.buf, state->in.pos);

                    stop = (msg_handler(context, &reply, msg_handler_data) != 0);
                }

                if (stop) {
                    *winner_out = state;
                    return TRUE;
                }
            }
        }
    }
    if (e != 0)
        return TRUE;
    return FALSE;
}

/*
 * Current worst-case timeout behavior:
 *
 * First pass, 1s per udp or tcp server, plus 2s at end.
 * Second pass, 1s per udp server, plus 4s.
 * Third pass, 1s per udp server, plus 8s.
 * Fourth => 16s, etc.
 *
 * Restated:
 * Per UDP server, 1s per pass.
 * Per TCP server, 1s.
 * Backoff delay, 2**(P+1) - 2, where P is total number of passes.
 *
 * Total = 2**(P+1) + U*P + T - 2.
 *
 * If P=3, Total = 3*U + T + 14.
 * If P=4, Total = 4*U + T + 30.
 *
 * Note that if you try to reach two ports (e.g., both 88 and 750) on
 * one server, it counts as two.
 *
 * There is one exception to the above rules.  Whenever a TCP connection is
 * established, we wait up to ten seconds for it to finish or fail before
 * moving on.  This reduces network traffic significantly in a TCP environment.
 */

krb5_error_code
k5_sendto(krb5_context context, const krb5_data *message,
          const krb5_data *realm, const struct serverlist *servers,
          k5_transport_strategy strategy,
          struct sendto_callback_info* callback_info, krb5_data *reply,
          struct sockaddr *remoteaddr, socklen_t *remoteaddrlen,
          int *server_used,
          /* return 0 -> keep going, 1 -> quit */
          int (*msg_handler)(krb5_context, const krb5_data *, void *),
          void *msg_handler_data)
{
    int pass;
    time_ms delay;
    krb5_error_code retval;
    struct conn_state *conns = NULL, *state, **tailptr, *next, *winner;
    size_t s;
    struct select_state *sel_state = NULL, *seltemp;
    char *udpbuf = NULL;
    krb5_boolean done = FALSE;

    *reply = empty_data();

    /* One for use here, listing all our fds in use, and one for
     * temporary use in service_fds, for the fds of interest.  */
    sel_state = malloc(2 * sizeof(*sel_state));
    if (sel_state == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }
    seltemp = &sel_state[1];
    cm_init_selstate(sel_state);

    /* First pass: resolve server hosts, communicate with resulting addresses
     * of the preferred transport, and wait 1s for an answer from each. */
    for (s = 0; s < servers->nservers && !done; s++) {
        /* Find the current tail pointer. */
        for (tailptr = &conns; *tailptr != NULL; tailptr = &(*tailptr)->next);
        retval = resolve_server(context, realm, servers, s, strategy, message,
                                &udpbuf, &conns);
        if (retval)
            goto cleanup;
        for (state = *tailptr; state != NULL && !done; state = state->next) {
            /* Contact each new connection, deferring those which use the
             * non-preferred RFC 4120 transport. */
            if (state->defer)
                continue;
            if (maybe_send(context, state, message, sel_state, realm,
                           callback_info))
                continue;
            done = service_fds(context, sel_state, 1000, conns, seltemp,
                               realm, msg_handler, msg_handler_data, &winner);
        }
    }

    /* Complete the first pass by contacting servers of the non-preferred RFC
     * 4120 transport (if given), waiting 1s for an answer from each. */
    for (state = conns; state != NULL && !done; state = state->next) {
        if (!state->defer)
            continue;
        if (maybe_send(context, state, message, sel_state, realm,
                       callback_info))
            continue;
        done = service_fds(context, sel_state, 1000, conns, seltemp,
                           realm, msg_handler, msg_handler_data, &winner);
    }

    /* Wait for two seconds at the end of the first pass. */
    if (!done) {
        done = service_fds(context, sel_state, 2000, conns, seltemp,
                           realm, msg_handler, msg_handler_data, &winner);
    }

    /* Make remaining passes over all of the connections. */
    delay = 4000;
    for (pass = 1; pass < MAX_PASS && !done; pass++) {
        for (state = conns; state != NULL && !done; state = state->next) {
            if (maybe_send(context, state, message, sel_state, realm,
                           callback_info))
                continue;
            done = service_fds(context, sel_state, 1000, conns, seltemp,
                               realm, msg_handler, msg_handler_data, &winner);
            if (sel_state->nfds == 0)
                break;
        }
        /* Wait for the delay backoff at the end of this pass. */
        if (!done) {
            done = service_fds(context, sel_state, delay, conns, seltemp,
                               realm, msg_handler, msg_handler_data, &winner);
        }
        if (sel_state->nfds == 0)
            break;
        delay *= 2;
    }

    if (sel_state->nfds == 0 || !done || winner == NULL) {
        retval = KRB5_KDC_UNREACH;
        goto cleanup;
    }
    /* Success!  */
    *reply = make_data(winner->in.buf, winner->in.pos);
    retval = 0;
    winner->in.buf = NULL;
    if (server_used != NULL)
        *server_used = winner->server_index;
    if (remoteaddr != NULL && remoteaddrlen != 0 && *remoteaddrlen > 0)
        (void)getpeername(winner->fd, remoteaddr, remoteaddrlen);
    TRACE_SENDTO_KDC_RESPONSE(context, reply->length, &winner->addr);

cleanup:
    for (state = conns; state != NULL; state = next) {
        next = state->next;
        if (state->fd != INVALID_SOCKET) {
            if (socktype_for_transport(state->addr.transport) == SOCK_STREAM)
                TRACE_SENDTO_KDC_TCP_DISCONNECT(context, &state->addr);
            closesocket(state->fd);
            free_http_ssl_data(state);
        }
        if (state->state == READING && state->in.buf != udpbuf)
            free(state->in.buf);
        if (callback_info) {
            callback_info->pfn_cleanup(callback_info->data,
                                       &state->callback_buffer);
        }
        free(state);
    }

    if (reply->data != udpbuf)
        free(udpbuf);
    free(sel_state);
    return retval;
}
