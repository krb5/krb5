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

typedef krb5_int64 time_ms;

/* Since fd_set is large on some platforms (8K on AIX 5.2), this probably
 * shouldn't be allocated in automatic storage. */
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
struct incoming_krb5_message {
    size_t bufsizebytes_read;
    size_t bufsize;
    char *buf;
    char *pos;
    unsigned char bufsizebytes[4];
    size_t n_left;
};

struct conn_state {
    SOCKET fd;
    enum conn_states state;
    int (*service)(krb5_context context, struct conn_state *,
                   struct select_state *, int);
    struct remote_address addr;
    struct {
        struct {
            sg_buf sgbuf[2];
            sg_buf *sgp;
            int sg_count;
            unsigned char msg_len_buf[4];
        } out;
        struct incoming_krb5_message in;
    } x;
    krb5_data callback_buffer;
    size_t server_index;
    struct conn_state *next;
    time_ms endtime;
};

static int
in_addrlist(struct server_entry *entry, struct serverlist *list)
{
    size_t i;
    struct server_entry *le;

    for (i = 0; i < list->nservers; i++) {
        le = &list->servers[i];
        if (entry->hostname != NULL && le->hostname != NULL &&
            strcmp(entry->hostname, le->hostname) == 0)
            return 1;
        if (entry->hostname == NULL && le->hostname == NULL &&
            entry->addrlen == le->addrlen &&
            memcmp(&entry->addr, &le->addr, entry->addrlen) == 0)
            return 1;
    }
    return 0;
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
                int tcp_only)
{
    krb5_error_code retval, err;
    struct serverlist servers;
    int socktype1 = 0, socktype2 = 0, server_used;

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

    TRACE_SENDTO_KDC(context, message->length, realm, *use_master, tcp_only);

    if (!tcp_only && context->udp_pref_limit < 0) {
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

    if (tcp_only)
        socktype1 = SOCK_STREAM, socktype2 = 0;
    else if (message->length <= (unsigned int) context->udp_pref_limit)
        socktype1 = SOCK_DGRAM, socktype2 = SOCK_STREAM;
    else
        socktype1 = SOCK_STREAM, socktype2 = SOCK_DGRAM;

    retval = k5_locate_kdc(context, realm, &servers, *use_master,
                           tcp_only ? SOCK_STREAM : 0);
    if (retval)
        return retval;

    retval = k5_sendto(context, message, &servers, socktype1, socktype2,
                       NULL, reply, NULL, NULL, &server_used,
                       check_for_svc_unavailable, &err);
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
        struct serverlist mservers;
        struct server_entry *entry = &servers.servers[server_used];
        retval = k5_locate_kdc(context, realm, &mservers, TRUE,
                               entry->socktype);
        if (retval == 0) {
            if (in_addrlist(entry, &mservers))
                *use_master = 1;
            k5_free_serverlist(&mservers);
        }
        TRACE_SENDTO_KDC_MASTER(context, *use_master);
        retval = 0;
    }

cleanup:
    k5_free_serverlist(&servers);
    return retval;
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

static void
cm_init_selstate(struct select_state *selstate)
{
    selstate->nfds = 0;
#ifndef USE_POLL
    selstate->max = 0;
    FD_ZERO(&selstate->rfds);
    FD_ZERO(&selstate->wfds);
    FD_ZERO(&selstate->xfds);
#endif
}

static krb5_boolean
cm_add_fd(struct select_state *selstate, int fd, unsigned int ssflags)
{
#ifdef USE_POLL
    if (selstate->nfds >= MAX_POLLFDS)
        return FALSE;
    selstate->fds[selstate->nfds].fd = fd;
    selstate->fds[selstate->nfds].events = 0;
    if (ssflags & SSF_READ)
        selstate->fds[selstate->nfds].events |= POLLIN;
    if (ssflags & SSF_WRITE)
        selstate->fds[selstate->nfds].events |= POLLOUT;
#else
#ifndef _WIN32  /* On Windows FD_SETSIZE is a count, not a max value. */
    if (fd >= FD_SETSIZE)
        return FALSE;
#endif
    if (ssflags & SSF_READ)
        FD_SET(fd, &selstate->rfds);
    if (ssflags & SSF_WRITE)
        FD_SET(fd, &selstate->wfds);
    if (ssflags & SSF_EXCEPTION)
        FD_SET(fd, &selstate->xfds);
    if (selstate->max <= fd)
        selstate->max = fd + 1;
#endif
    selstate->nfds++;
    return TRUE;
}

static void
cm_remove_fd(struct select_state *selstate, int fd)
{
#ifdef USE_POLL
    int i;

    /* Find the FD in the array and move the last entry to its place. */
    assert(selstate->nfds > 0);
    for (i = 0; i < selstate->nfds && selstate->fds[i].fd != fd; i++);
    assert(i < selstate->nfds);
    selstate->fds[i] = selstate->fds[selstate->nfds - 1];
#else
    FD_CLR(fd, &selstate->rfds);
    FD_CLR(fd, &selstate->wfds);
    FD_CLR(fd, &selstate->xfds);
    if (selstate->max == 1 + fd) {
        while (selstate->max > 0
               && ! FD_ISSET(selstate->max-1, &selstate->rfds)
               && ! FD_ISSET(selstate->max-1, &selstate->wfds)
               && ! FD_ISSET(selstate->max-1, &selstate->xfds))
            selstate->max--;
    }
#endif
    selstate->nfds--;
}

static void
cm_unset_write(struct select_state *selstate, int fd)
{
#ifdef USE_POLL
    int i;

    for (i = 0; i < selstate->nfds && selstate->fds[i].fd != fd; i++);
    assert(i < selstate->nfds);
    selstate->fds[i].events &= ~POLLOUT;
#else
    FD_CLR(fd, &selstate->wfds);
#endif
}

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

static unsigned int
cm_get_ssflags(struct select_state *selstate, int fd)
{
    unsigned int ssflags = 0;
#ifdef USE_POLL
    int i;

    for (i = 0; i < selstate->nfds && selstate->fds[i].fd != fd; i++);
    assert(i < selstate->nfds);
    if (selstate->fds[i].revents & POLLIN)
        ssflags |= SSF_READ;
    if (selstate->fds[i].revents & POLLOUT)
        ssflags |= SSF_WRITE;
    if (selstate->fds[i].revents & POLLERR)
        ssflags |= SSF_EXCEPTION;
#else
    if (FD_ISSET(fd, &selstate->rfds))
        ssflags |= SSF_READ;
    if (FD_ISSET(fd, &selstate->wfds))
        ssflags |= SSF_WRITE;
    if (FD_ISSET(fd, &selstate->xfds))
        ssflags |= SSF_EXCEPTION;
#endif
    return ssflags;
}

static int service_tcp_fd(krb5_context context, struct conn_state *conn,
                          struct select_state *selstate, int ssflags);
static int service_udp_fd(krb5_context context, struct conn_state *conn,
                          struct select_state *selstate, int ssflags);

static void
set_conn_state_msg_length (struct conn_state *state, const krb5_data *message)
{
    if (!message || message->length == 0)
        return;

    if (state->addr.type == SOCK_STREAM) {
        store_32_be(message->length, state->x.out.msg_len_buf);
        SG_SET(&state->x.out.sgbuf[0], state->x.out.msg_len_buf, 4);
        SG_SET(&state->x.out.sgbuf[1], message->data, message->length);
        state->x.out.sg_count = 2;

    } else {

        SG_SET(&state->x.out.sgbuf[0], message->data, message->length);
        SG_SET(&state->x.out.sgbuf[1], 0, 0);
        state->x.out.sg_count = 1;

    }
}

static krb5_error_code
add_connection(struct conn_state **conns, struct addrinfo *ai,
               size_t server_index, const krb5_data *message, char **udpbufp)
{
    struct conn_state *state, **tailptr;

    state = calloc(1, sizeof(*state));
    if (state == NULL)
        return ENOMEM;
    state->state = INITIALIZING;
    state->x.out.sgp = state->x.out.sgbuf;
    state->addr.type = ai->ai_socktype;
    state->addr.family = ai->ai_family;
    state->addr.len = ai->ai_addrlen;
    memcpy(&state->addr.saddr, ai->ai_addr, ai->ai_addrlen);
    state->fd = INVALID_SOCKET;
    state->server_index = server_index;
    SG_SET(&state->x.out.sgbuf[1], 0, 0);
    if (ai->ai_socktype == SOCK_STREAM) {
        state->service = service_tcp_fd;
        set_conn_state_msg_length (state, message);
    } else {
        state->service = service_udp_fd;
        set_conn_state_msg_length (state, message);

        if (*udpbufp == NULL) {
            *udpbufp = malloc(MAX_DGRAM_SIZE);
            if (*udpbufp == 0)
                return ENOMEM;
        }
        state->x.in.buf = *udpbufp;
        state->x.in.bufsize = MAX_DGRAM_SIZE;
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
               size_t ind, int socktype1, int socktype2,
               const krb5_data *message, char **udpbufp,
               struct conn_state **conns)
{
    krb5_error_code retval;
    struct server_entry *entry = &servers->servers[ind];
    struct addrinfo *addrs, *a, hint, ai;
    int err, result;
    char portbuf[64];

    /* Skip any stray entries of socktypes we don't want. */
    if (entry->socktype != 0 && entry->socktype != socktype1 &&
        entry->socktype != socktype2)
        return 0;

    if (entry->hostname == NULL) {
        ai.ai_socktype = entry->socktype;
        ai.ai_family = entry->family;
        ai.ai_addrlen = entry->addrlen;
        ai.ai_addr = (struct sockaddr *)&entry->addr;
        return add_connection(conns, &ai, ind, message, udpbufp);
    }

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = entry->family;
    hint.ai_socktype = (entry->socktype != 0) ? entry->socktype : socktype1;
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
    /* Add each address with the preferred socktype. */
    retval = 0;
    for (a = addrs; a != 0 && retval == 0; a = a->ai_next)
        retval = add_connection(conns, a, ind, message, udpbufp);
    if (retval == 0 && entry->socktype == 0 && socktype2 != 0) {
        /* Add each address again with the non-preferred socktype. */
        for (a = addrs; a != 0 && retval == 0; a = a->ai_next) {
            a->ai_socktype = socktype2;
            retval = add_connection(conns, a, ind, message, udpbufp);
        }
    }
    freeaddrinfo(addrs);
    return retval;
}

static int
start_connection(krb5_context context, struct conn_state *state,
                 struct select_state *selstate,
                 struct sendto_callback_info *callback_info)
{
    int fd, e;
    unsigned int ssflags;
    static const int one = 1;
    static const struct linger lopt = { 0, 0 };

    fd = socket(state->addr.family, state->addr.type, 0);
    if (fd == INVALID_SOCKET)
        return -1;              /* try other hosts */
    set_cloexec_fd(fd);
    /* Make it non-blocking.  */
    ioctlsocket(fd, FIONBIO, (const void *) &one);
    if (state->addr.type == SOCK_STREAM) {
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

        set_conn_state_msg_length(state, &state->callback_buffer);
    }

    if (state->addr.type == SOCK_DGRAM) {
        /* Send it now.  */
        ssize_t ret;
        sg_buf *sg = &state->x.out.sgbuf[0];

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
    ssflags = SSF_READ | SSF_EXCEPTION;
    if (state->state == CONNECTING || state->state == WRITING)
        ssflags |= SSF_WRITE;
    if (!cm_add_fd(selstate, state->fd, ssflags)) {
        (void) closesocket(state->fd);
        state->fd = INVALID_SOCKET;
        state->state = FAILED;
        return -1;
    }

    return 0;
}

/* Return 0 if we sent something, non-0 otherwise.
   If 0 is returned, the caller should delay waiting for a response.
   Otherwise, the caller should immediately move on to process the
   next connection.  */
static int
maybe_send(krb5_context context, struct conn_state *conn,
           struct select_state *selstate,
           struct sendto_callback_info *callback_info)
{
    sg_buf *sg;
    ssize_t ret;

    if (conn->state == INITIALIZING)
        return start_connection(context, conn, selstate, callback_info);

    /* Did we already shut down this channel?  */
    if (conn->state == FAILED) {
        return -1;
    }

    if (conn->addr.type == SOCK_STREAM) {
        /* The select callback will handle flushing any data we
           haven't written yet, and we only write it once.  */
        return -1;
    }

    /* UDP - retransmit after a previous attempt timed out. */
    sg = &conn->x.out.sgbuf[0];
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

    /* Check for a socket exception or readable data before we expect it. */
    if (ssflags & SSF_EXCEPTION ||
        ((ssflags & SSF_READ) && conn->state != READING))
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
        nwritten = SOCKET_WRITEV(conn->fd, conn->x.out.sgp,
                                 conn->x.out.sg_count, tmp);
        if (nwritten < 0) {
            TRACE_SENDTO_KDC_TCP_ERROR_SEND(context, &conn->addr,
                                            SOCKET_ERRNO);
            goto kill_conn;
        }
        while (nwritten) {
            sg_buf *sgp = conn->x.out.sgp;
            if ((size_t) nwritten < SG_LEN(sgp)) {
                SG_ADVANCE(sgp, (size_t) nwritten);
                nwritten = 0;
            } else {
                nwritten -= SG_LEN(sgp);
                conn->x.out.sgp++;
                conn->x.out.sg_count--;
            }
        }
        if (conn->x.out.sg_count == 0) {
            /* Done writing, switch to reading. */
            cm_unset_write(selstate, conn->fd);
            conn->state = READING;
            conn->x.in.bufsizebytes_read = 0;
            conn->x.in.bufsize = 0;
            conn->x.in.buf = 0;
            conn->x.in.pos = 0;
            conn->x.in.n_left = 0;
        }
        return 0;

    case READING:
        if (conn->x.in.bufsizebytes_read == 4) {
            /* Reading data.  */
            nread = SOCKET_READ(conn->fd, conn->x.in.pos, conn->x.in.n_left);
            if (nread <= 0) {
                e = nread ? SOCKET_ERRNO : ECONNRESET;
                TRACE_SENDTO_KDC_TCP_ERROR_RECV(context, &conn->addr, e);
                goto kill_conn;
            }
            conn->x.in.n_left -= nread;
            conn->x.in.pos += nread;
            if (conn->x.in.n_left <= 0)
                return 1;
        } else {
            /* Reading length.  */
            nread = SOCKET_READ(conn->fd,
                                conn->x.in.bufsizebytes + conn->x.in.bufsizebytes_read,
                                4 - conn->x.in.bufsizebytes_read);
            if (nread <= 0) {
                e = nread ? SOCKET_ERRNO : ECONNRESET;
                TRACE_SENDTO_KDC_TCP_ERROR_RECV_LEN(context, &conn->addr, e);
                goto kill_conn;
            }
            conn->x.in.bufsizebytes_read += nread;
            if (conn->x.in.bufsizebytes_read == 4) {
                unsigned long len = load_32_be (conn->x.in.bufsizebytes);
                /* Arbitrary 1M cap.  */
                if (len > 1 * 1024 * 1024)
                    goto kill_conn;
                conn->x.in.bufsize = conn->x.in.n_left = len;
                conn->x.in.buf = conn->x.in.pos = malloc(len);
                if (conn->x.in.buf == 0)
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

    nread = recv(conn->fd, conn->x.in.buf, conn->x.in.bufsize, 0);
    if (nread < 0) {
        TRACE_SENDTO_KDC_UDP_ERROR_RECV(context, &conn->addr, SOCKET_ERRNO);
        kill_conn(conn, selstate);
        return 0;
    }
    conn->x.in.pos = conn->x.in.buf + nread;
    return 1;
}

/* Return the maximum of endtime and the endtime fields of all currently active
 * TCP connections. */
static time_ms
get_endtime(time_ms endtime, struct conn_state *conns)
{
    struct conn_state *state;

    for (state = conns; state != NULL; state = state->next) {
        if (state->addr.type == SOCK_STREAM &&
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
                    krb5_data reply;

                    reply.data = state->x.in.buf;
                    reply.length = state->x.in.pos - state->x.in.buf;

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
          const struct serverlist *servers, int socktype1, int socktype2,
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

    reply->data = 0;
    reply->length = 0;

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
     * of the preferred socktype, and wait 1s for an answer from each. */
    for (s = 0; s < servers->nservers && !done; s++) {
        /* Find the current tail pointer. */
        for (tailptr = &conns; *tailptr != NULL; tailptr = &(*tailptr)->next);
        retval = resolve_server(context, servers, s, socktype1, socktype2,
                                message, &udpbuf, &conns);
        if (retval)
            goto cleanup;
        for (state = *tailptr; state != NULL && !done; state = state->next) {
            /* Contact each new connection whose socktype matches socktype1. */
            if (state->addr.type != socktype1)
                continue;
            if (maybe_send(context, state, sel_state, callback_info))
                continue;
            done = service_fds(context, sel_state, 1000, conns, seltemp,
                               msg_handler, msg_handler_data, &winner);
        }
    }

    /* Complete the first pass by contacting servers of the non-preferred
     * socktype (if given), waiting 1s for an answer from each. */
    for (state = conns; state != NULL && !done; state = state->next) {
        if (state->addr.type != socktype2)
            continue;
        if (maybe_send(context, state, sel_state, callback_info))
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
            if (maybe_send(context, state, sel_state, callback_info))
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
    reply->data = winner->x.in.buf;
    reply->length = winner->x.in.pos - winner->x.in.buf;
    retval = 0;
    winner->x.in.buf = NULL;
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
        if (state->state == READING && state->x.in.buf != udpbuf)
            free(state->x.in.buf);
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
