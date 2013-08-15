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

/* Send packet to KDC for realm; wait for response, retransmitting
 * as necessary. */

#include "fake-addrinfo.h"
#include "k5-int.h"

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

static const char *const state_strings[] = {
    "INITIALIZING", "CONNECTING", "WRITING", "READING", "FAILED"
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

struct conn_state {
    SOCKET fd;
    enum conn_states state;
    int (*service)(krb5_context context, struct conn_state *,
                   struct select_state *, int);
    struct remote_address addr;
    struct incoming_message in;
    struct outgoing_message out;
    krb5_data callback_buffer;
    size_t server_index;
    struct conn_state *next;
    time_ms endtime;
    krb5_boolean defer;
};

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
    retval = k5_sendto(context, message, &servers, strategy, NULL, reply,
                       NULL, NULL, &server_used, check_for_svc_unavailable,
                       &err);
    if (retval == KRB5_KDC_UNREACH) {
        if (err == KDC_ERR_SVC_UNAVAILABLE) {
            retval = KRB5KDC_ERR_SVC_UNAVAILABLE;
        } else {
            krb5_set_error_message(context, retval,
                                   _("Cannot contact any KDC for realm "
                                     "'%.*s'"), realm->length, realm->data);
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

static int service_tcp_fd(krb5_context context, struct conn_state *conn,
                          struct select_state *selstate, int ssflags);
static int service_udp_fd(krb5_context context, struct conn_state *conn,
                          struct select_state *selstate, int ssflags);

/* Set up the actual message we will send across the underlying transport to
 * communicate the payload message, using one or both of state->out.sgbuf. */
static void
set_transport_message(struct conn_state *state, const krb5_data *message)
{
    struct outgoing_message *out = &state->out;

    if (message == NULL || message->length == 0)
        return;

    if (state->addr.transport == TCP) {
        store_32_be(message->length, out->msg_len_buf);
        SG_SET(&out->sgbuf[0], out->msg_len_buf, 4);
        SG_SET(&out->sgbuf[1], message->data, message->length);
        out->sg_count = 2;
    } else {
        SG_SET(&out->sgbuf[0], message->data, message->length);
        SG_SET(&out->sgbuf[1], NULL, 0);
        out->sg_count = 1;
    }
}

static krb5_error_code
add_connection(struct conn_state **conns, k5_transport transport,
               krb5_boolean defer, struct addrinfo *ai, size_t server_index,
               char **udpbufp)
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
        state->service = service_tcp_fd;
    } else {
        state->service = service_udp_fd;

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
resolve_server(krb5_context context, const struct serverlist *servers,
               size_t ind, k5_transport_strategy strategy,
               const krb5_data *message, char **udpbufp,
               struct conn_state **conns)
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
        return add_connection(conns, entry->transport, defer, &ai, ind,
                              udpbufp);
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
    for (a = addrs; a != 0 && retval == 0; a = a->ai_next)
        retval = add_connection(conns, transport, FALSE, a, ind, udpbufp);

    /* For TCP_OR_UDP entries, add each address again with the non-preferred
     * transport, unless we are avoiding UDP.  Flag these as deferred. */
    if (retval == 0 && entry->transport == TCP_OR_UDP && strategy != NO_UDP) {
        transport = (strategy == UDP_FIRST) ? TCP : UDP;
        for (a = addrs; a != 0 && retval == 0; a = a->ai_next) {
            a->ai_socktype = socktype_for_transport(transport);
            retval = add_connection(conns, transport, TRUE, a, ind, udpbufp);
        }
    }
    freeaddrinfo(addrs);
    return retval;
}

static int
start_connection(krb5_context context, struct conn_state *state,
                 const krb5_data *message, struct select_state *selstate,
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
    set_transport_message(state, message);

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
            return -4;
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
           struct sendto_callback_info *callback_info)
{
    sg_buf *sg;
    ssize_t ret;

    if (conn->state == INITIALIZING) {
        return start_connection(context, conn, message, selstate,
                                callback_info);
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
kill_conn(struct conn_state *conn, struct select_state *selstate)
{
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

/* Process events on a TCP socket.  Return 1 if we get a complete reply. */
static int
service_tcp_fd(krb5_context context, struct conn_state *conn,
               struct select_state *selstate, int ssflags)
{
    int e = 0;
    ssize_t nwritten, nread;
    SOCKET_WRITEV_TEMP tmp;
    struct incoming_message *in = &conn->in;
    struct outgoing_message *out = &conn->out;

    /* Check for a socket exception. */
    if (ssflags & SSF_EXCEPTION)
        goto kill_conn;

    switch (conn->state) {
    case CONNECTING:
        /* Check whether the connection succeeded. */
        e = get_so_error(conn->fd);
        if (e) {
            TRACE_SENDTO_KDC_TCP_ERROR_CONNECT(context, &conn->addr, e);
            goto kill_conn;
        }
        conn->state = WRITING;

        /* Record this connection's timeout for service_fds. */
        if (get_curtime_ms(&conn->endtime) == 0)
            conn->endtime += 10000;

        /* Fall through. */
    case WRITING:
        TRACE_SENDTO_KDC_TCP_SEND(context, &conn->addr);
        nwritten = SOCKET_WRITEV(conn->fd, out->sgp, out->sg_count, tmp);
        if (nwritten < 0) {
            TRACE_SENDTO_KDC_TCP_ERROR_SEND(context, &conn->addr,
                                            SOCKET_ERRNO);
            goto kill_conn;
        }
        while (nwritten) {
            sg_buf *sgp = out->sgp;
            if ((size_t) nwritten < SG_LEN(sgp)) {
                SG_ADVANCE(sgp, (size_t) nwritten);
                nwritten = 0;
            } else {
                nwritten -= SG_LEN(sgp);
                out->sgp++;
                out->sg_count--;
            }
        }
        if (out->sg_count == 0) {
            /* Done writing, switch to reading. */
            cm_read(selstate, conn->fd);
            conn->state = READING;
            in->bufsizebytes_read = 0;
            in->bufsize = 0;
            in->pos = 0;
            in->buf = NULL;
            in->n_left = 0;
        }
        return 0;

    case READING:
        if (in->bufsizebytes_read == 4) {
            /* Reading data.  */
            nread = SOCKET_READ(conn->fd, &in->buf[in->pos], in->n_left);
            if (nread <= 0) {
                e = nread ? SOCKET_ERRNO : ECONNRESET;
                TRACE_SENDTO_KDC_TCP_ERROR_RECV(context, &conn->addr, e);
                goto kill_conn;
            }
            in->n_left -= nread;
            in->pos += nread;
            if (in->n_left <= 0)
                return 1;
        } else {
            /* Reading length.  */
            nread = SOCKET_READ(conn->fd,
                                in->bufsizebytes + in->bufsizebytes_read,
                                4 - in->bufsizebytes_read);
            if (nread <= 0) {
                e = nread ? SOCKET_ERRNO : ECONNRESET;
                TRACE_SENDTO_KDC_TCP_ERROR_RECV_LEN(context, &conn->addr, e);
                goto kill_conn;
            }
            in->bufsizebytes_read += nread;
            if (in->bufsizebytes_read == 4) {
                unsigned long len = load_32_be(in->bufsizebytes);
                /* Arbitrary 1M cap.  */
                if (len > 1 * 1024 * 1024)
                    goto kill_conn;
                in->bufsize = in->n_left = len;
                in->pos = 0;
                in->buf = malloc(len);
                if (in->buf == NULL)
                    goto kill_conn;
            }
        }
        break;

    default:
        abort();
    }
    return 0;

kill_conn:
    TRACE_SENDTO_KDC_TCP_DISCONNECT(context, &conn->addr);
    kill_conn(conn, selstate);
    return 0;
}

/* Process events on a UDP socket.  Return 1 if we get a reply. */
static int
service_udp_fd(krb5_context context, struct conn_state *conn,
               struct select_state *selstate, int ssflags)
{
    int nread;

    if (!(ssflags & (SSF_READ|SSF_EXCEPTION)))
        abort();
    if (conn->state != READING)
        abort();

    nread = recv(conn->fd, conn->in.buf, conn->in.bufsize, 0);
    if (nread < 0) {
        TRACE_SENDTO_KDC_UDP_ERROR_RECV(context, &conn->addr, SOCKET_ERRNO);
        kill_conn(conn, selstate);
        return 0;
    }
    conn->in.pos = nread;
    return 1;
}

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
            struct select_state *seltemp,
            int (*msg_handler)(krb5_context, const krb5_data *, void *),
            void *msg_handler_data, struct conn_state **winner_out)
{
    int e, selret = 0;
    time_ms endtime;
    struct conn_state *state;

    *winner_out = NULL;

    e = get_curtime_ms(&endtime);
    if (e)
        return 1;
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
            return 0;

        /* Got something on a socket, process it.  */
        for (state = conns; state != NULL; state = state->next) {
            int ssflags;

            if (state->fd == INVALID_SOCKET)
                continue;
            ssflags = cm_get_ssflags(seltemp, state->fd);
            if (!ssflags)
                continue;

            if (state->service(context, state, selstate, ssflags)) {
                int stop = 1;

                if (msg_handler != NULL) {
                    krb5_data reply = make_data(state->in.buf, state->in.pos);

                    stop = (msg_handler(context, &reply, msg_handler_data) != 0);
                }

                if (stop) {
                    *winner_out = state;
                    return 1;
                }
            }
        }
    }
    if (e != 0)
        return 1;
    return 0;
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
          const struct serverlist *servers, k5_transport_strategy strategy,
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
        retval = resolve_server(context, servers, s, strategy, message,
                                &udpbuf, &conns);
        if (retval)
            goto cleanup;
        for (state = *tailptr; state != NULL && !done; state = state->next) {
            /* Contact each new connection, deferring those which use the
             * non-preferred RFC 4120 transport. */
            if (state->defer)
                continue;
            if (maybe_send(context, state, message, sel_state, callback_info))
                continue;
            done = service_fds(context, sel_state, 1000, conns, seltemp,
                               msg_handler, msg_handler_data, &winner);
        }
    }

    /* Complete the first pass by contacting servers of the non-preferred RFC
     * 4120 transport (if given), waiting 1s for an answer from each. */
    for (state = conns; state != NULL && !done; state = state->next) {
        if (!state->defer)
            continue;
        if (maybe_send(context, state, message, sel_state, callback_info))
            continue;
        done = service_fds(context, sel_state, 1000, conns, seltemp,
                           msg_handler, msg_handler_data, &winner);
    }

    /* Wait for two seconds at the end of the first pass. */
    if (!done) {
        done = service_fds(context, sel_state, 2000, conns, seltemp,
                           msg_handler, msg_handler_data, &winner);
    }

    /* Make remaining passes over all of the connections. */
    delay = 4000;
    for (pass = 1; pass < MAX_PASS && !done; pass++) {
        for (state = conns; state != NULL && !done; state = state->next) {
            if (maybe_send(context, state, message, sel_state, callback_info))
                continue;
            done = service_fds(context, sel_state, 1000, conns, seltemp,
                               msg_handler, msg_handler_data, &winner);
            if (sel_state->nfds == 0)
                break;
        }
        /* Wait for the delay backoff at the end of this pass. */
        if (!done) {
            done = service_fds(context, sel_state, delay, conns, seltemp,
                               msg_handler, msg_handler_data, &winner);
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
        if (state->fd != INVALID_SOCKET)
            closesocket(state->fd);
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
