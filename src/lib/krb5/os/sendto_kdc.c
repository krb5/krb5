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
#ifdef _WIN32
#include <sys/timeb.h>
#endif

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

#undef DEBUG

#ifdef DEBUG
int krb5int_debug_sendto_kdc = 0;
#define debug krb5int_debug_sendto_kdc

static void
default_debug_handler (const void *data, size_t len)
{
#if 0
    static FILE *logfile;
    if (logfile == NULL) {
        logfile = fopen("/tmp/sendto_kdc.log", "a");
        if (logfile == NULL)
            return;
        setbuf(logfile, NULL);
    }
    fwrite(data, 1, len, logfile);
#else
    fwrite(data, 1, len, stderr);
    /* stderr is unbuffered */
#endif
}

void (*krb5int_sendtokdc_debug_handler) (const void *, size_t) = default_debug_handler;

static void
put(const void *ptr, size_t len)
{
    (*krb5int_sendtokdc_debug_handler)(ptr, len);
}
static void
putstr(const char *str)
{
    put(str, strlen(str));
}
#else
void (*krb5int_sendtokdc_debug_handler) (const void *, size_t) = 0;
#endif

#define dprint krb5int_debug_fprint
void
krb5int_debug_fprint (const char *fmt, ...)
{
#ifdef DEBUG
    va_list args;

    /* Temporaries for variable arguments, etc.  */
    krb5_error_code kerr;
    int err;
    fd_set *rfds, *wfds, *xfds;
    int i;
    int maxfd;
    struct timeval *tv;
    struct addrinfo *ai;
    const krb5_data *d;
    char addrbuf[NI_MAXHOST], portbuf[NI_MAXSERV];
    const char *p;
#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif
    char tmpbuf[max(NI_MAXHOST + NI_MAXSERV + 30, 200)];
    struct k5buf buf;

    if (!krb5int_debug_sendto_kdc)
        return;

    va_start(args, fmt);

#define putf(FMT,X)     (snprintf(tmpbuf,sizeof(tmpbuf),FMT,X),putstr(tmpbuf))

    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            const char *fmt2;
            size_t len;
            for (fmt2 = fmt+1; *fmt2; fmt2++)
                if (*fmt2 == '%')
                    break;
            len = fmt2 - fmt;
            put(fmt, len);
            fmt += len - 1;     /* then fmt++ in loop header */
            continue;
        }
        /* After this, always processing a '%' sequence.  */
        fmt++;
        switch (*fmt) {
        case 0:
        default:
            abort();
        case 'E':
            /* %E => krb5_error_code */
            kerr = va_arg(args, krb5_error_code);
            snprintf(tmpbuf, sizeof(tmpbuf), "%lu/", (unsigned long) kerr);
            putstr(tmpbuf);
            p = error_message(kerr);
            putstr(p);
            break;
        case 'm':
            /* %m => errno value (int) */
            /* Like syslog's %m except the errno value is passed in
               rather than the current value.  */
            err = va_arg(args, int);
            putf("%d/", err);
            p = NULL;
#ifdef HAVE_STRERROR_R
            if (strerror_r(err, tmpbuf, sizeof(tmpbuf)) == 0)
                p = tmpbuf;
#endif
            if (p == NULL)
                p = strerror(err);
            putstr(p);
            break;
        case 's':
            /* %s => char * */
            p = va_arg(args, const char *);
            putstr(p);
            break;
        case 't':
            /* %t => struct timeval * */
            tv = va_arg(args, struct timeval *);
            if (tv) {
                snprintf(tmpbuf, sizeof(tmpbuf), "%ld.%06ld",
                         (long) tv->tv_sec, (long) tv->tv_usec);
                putstr(tmpbuf);
            } else
                putstr("never");
            break;
        case 'd':
            /* %d => int */
            putf("%d", va_arg(args, int));
            break;
        case 'p':
            /* %p => pointer */
            putf("%p", va_arg(args, void*));
            break;
        case 'A':
            /* %A => addrinfo */
            ai = va_arg(args, struct addrinfo *);
            krb5int_buf_init_dynamic(&buf);
            if (ai->ai_socktype == SOCK_DGRAM)
                krb5int_buf_add(&buf, "dgram");
            else if (ai->ai_socktype == SOCK_STREAM)
                krb5int_buf_add(&buf, "stream");
            else
                krb5int_buf_add_fmt(&buf, "socktype%d", ai->ai_socktype);

            if (0 != getnameinfo (ai->ai_addr, ai->ai_addrlen,
                                  addrbuf, sizeof (addrbuf),
                                  portbuf, sizeof (portbuf),
                                  NI_NUMERICHOST | NI_NUMERICSERV)) {
                if (ai->ai_addr->sa_family == AF_UNSPEC)
                    krb5int_buf_add(&buf, " AF_UNSPEC");
                else
                    krb5int_buf_add_fmt(&buf, " af%d", ai->ai_addr->sa_family);
            } else
                krb5int_buf_add_fmt(&buf, " %s.%s", addrbuf, portbuf);
            if (krb5int_buf_data(&buf))
                putstr(krb5int_buf_data(&buf));
            krb5int_free_buf(&buf);
            break;
        case 'D':
            /* %D => krb5_data * */
            d = va_arg(args, krb5_data *);
            /* may not be nul-terminated */
            put(d->data, d->length);
            break;
        }
    }
    va_end(args);
#endif
}

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

    dprint("krb5_sendto_kdc(%d@%p, \"%D\", use_master=%d, tcp_only=%d)\n",
           message->length, message->data, realm, *use_master, tcp_only);
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

#ifdef DEBUG

#ifdef _WIN32
#define dperror(MSG)                                    \
    dprint("%s: an error occurred ... "                 \
           "\tline=%d errno=%m socketerrno=%m\n",       \
           (MSG), __LINE__, errno, SOCKET_ERRNO)
#else
#define dperror(MSG) dprint("%s: %m\n", MSG, errno)
#endif
#define dfprintf(ARGLIST) (debug ? fprintf ARGLIST : 0)

#else /* ! DEBUG */

#define dperror(MSG) ((void)(MSG))
#define dfprintf(ARGLIST) ((void)0)

#endif

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

#include "cm.h"

/*
 * Currently only sendto_kdc.c knows how to use poll(); the other candidate
 * user, lib/apputils/net-server.c, is stuck using select() for the moment
 * since it is entangled with the RPC library.  The following cm_* functions
 * are not fully generic, are O(n^2) in the poll case, and are limited to
 * handling 1024 connections (in order to maintain a constant-sized selstate).
 * More rearchitecting would be appropriate before extending this support to
 * the KDC and kadmind.
 */

static void
cm_init_selstate(struct select_state *selstate)
{
    selstate->nfds = 0;
    selstate->end_time.tv_sec = selstate->end_time.tv_usec = 0;
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
        dprint("new max_fd + 1 is %d\n", selstate->max);
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
cm_select_or_poll(const struct select_state *in, struct select_state *out,
                  int *sret)
{
#ifdef USE_POLL
    struct timeval now;
    int e, timeout;

    if (in->end_time.tv_sec == 0)
        timeout = -1;
    else {
        e = k5_getcurtime(&now);
        if (e)
            return e;
        timeout = (in->end_time.tv_sec - now.tv_sec) * 1000 +
            (in->end_time.tv_usec - now.tv_usec) / 1000;
        if (timeout < 0) {
            *sret = 0;
            return 0;
        }
    }
    /* We don't need a separate copy of the selstate for poll, but use one
     * anyone for consistency with the select wrapper. */
    *out = *in;
    *sret = poll(out->fds, out->nfds, timeout);
    e = SOCKET_ERRNO;
    return (*sret < 0) ? e : 0;
#else
    /* Use the select wrapper from cm.c. */
    return krb5int_cm_call_select(in, out, sret);
#endif
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

    if (!state->is_udp) {

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
    state->err = 0;
    state->x.out.sgp = state->x.out.sgbuf;
    state->socktype = ai->ai_socktype;
    state->family = ai->ai_family;
    state->addrlen = ai->ai_addrlen;
    memcpy(&state->addr, ai->ai_addr, ai->ai_addrlen);
    state->fd = INVALID_SOCKET;
    state->server_index = server_index;
    SG_SET(&state->x.out.sgbuf[1], 0, 0);
    if (ai->ai_socktype == SOCK_STREAM) {
        /*
          SG_SET(&state->x.out.sgbuf[0], message_len_buf, 4);
          SG_SET(&state->x.out.sgbuf[1], message->data, message->length);
          state->x.out.sg_count = 2;
        */

        state->is_udp = 0;
        state->service = service_tcp_fd;
        set_conn_state_msg_length (state, message);
    } else {
        /*
          SG_SET(&state->x.out.sgbuf[0], message->data, message->length);
          SG_SET(&state->x.out.sgbuf[1], 0, 0);
          state->x.out.sg_count = 1;
        */

        state->is_udp = 1;
        state->service = service_udp_fd;
        set_conn_state_msg_length (state, message);

        if (*udpbufp == NULL) {
            *udpbufp = malloc(krb5_max_dgram_size);
            if (*udpbufp == 0)
                return ENOMEM;
        }
        state->x.in.buf = *udpbufp;
        state->x.in.bufsize = krb5_max_dgram_size;
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

    dprint("start_connection(@%p)\ngetting %s socket in family %d...", state,
           state->socktype == SOCK_STREAM ? "stream" : "dgram", state->family);
    fd = socket(state->family, state->socktype, 0);
    if (fd == INVALID_SOCKET) {
        state->err = SOCKET_ERRNO;
        dprint("socket: %m creating with af %d\n", state->err, state->family);
        return -1;              /* try other hosts */
    }
    set_cloexec_fd(fd);
    /* Make it non-blocking.  */
    if (ioctlsocket(fd, FIONBIO, (const void *) &one))
        dperror("sendto_kdc: ioctl(FIONBIO)");
    if (state->socktype == SOCK_STREAM) {
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt)))
            dperror("sendto_kdc: setsockopt(SO_LINGER)");
        TRACE_SENDTO_KDC_TCP_CONNECT(context, state);
    }

    /* Start connecting to KDC.  */
    e = connect(fd, (struct sockaddr *)&state->addr, state->addrlen);
    if (e != 0) {
        /*
         * This is the path that should be followed for non-blocking
         * connections.
         */
        if (SOCKET_ERRNO == EINPROGRESS || SOCKET_ERRNO == EWOULDBLOCK) {
            state->state = CONNECTING;
            state->fd = fd;
        } else {
            dprint("connect failed: %m\n", SOCKET_ERRNO);
            (void) closesocket(fd);
            state->err = SOCKET_ERRNO;
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
    dprint("new state = %s\n", state_strings[state->state]);


    /*
     * Here's where KPASSWD callback gets the socket information it needs for
     * a kpasswd request
     */
    if (callback_info) {

        e = callback_info->pfn_callback(state, callback_info->context,
                                        &state->callback_buffer);
        if (e != 0) {
            dprint("callback failed: %m\n", e);
            (void) closesocket(fd);
            state->err = e;
            state->fd = INVALID_SOCKET;
            state->state = FAILED;
            return -3;
        }

        set_conn_state_msg_length(state, &state->callback_buffer);
    }

    if (state->socktype == SOCK_DGRAM) {
        /* Send it now.  */
        ssize_t ret;
        sg_buf *sg = &state->x.out.sgbuf[0];

        TRACE_SENDTO_KDC_UDP_SEND_INITIAL(context, state);
        dprint("sending %d bytes on fd %d\n", SG_LEN(sg), state->fd);
        ret = send(state->fd, SG_BUF(sg), SG_LEN(sg), 0);
        if (ret < 0 || (size_t) ret != SG_LEN(sg)) {
            TRACE_SENDTO_KDC_UDP_ERROR_SEND_INITIAL(context, state,
                                                    SOCKET_ERRNO);
            dperror("sendto");
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

    dprint("maybe_send(@%p) state=%s type=%s\n", conn,
           state_strings[conn->state],
           conn->is_udp ? "udp" : "tcp");
    if (conn->state == INITIALIZING)
        return start_connection(context, conn, selstate, callback_info);

    /* Did we already shut down this channel?  */
    if (conn->state == FAILED) {
        dprint("connection already closed\n");
        return -1;
    }

    if (conn->socktype == SOCK_STREAM) {
        dprint("skipping stream socket\n");
        /* The select callback will handle flushing any data we
           haven't written yet, and we only write it once.  */
        return -1;
    }

    /* UDP - retransmit after a previous attempt timed out. */
    sg = &conn->x.out.sgbuf[0];
    TRACE_SENDTO_KDC_UDP_SEND_RETRY(context, conn);
    dprint("sending %d bytes on fd %d\n", SG_LEN(sg), conn->fd);
    ret = send(conn->fd, SG_BUF(sg), SG_LEN(sg), 0);
    if (ret < 0 || (size_t) ret != SG_LEN(sg)) {
        TRACE_SENDTO_KDC_UDP_ERROR_SEND_RETRY(context, conn, SOCKET_ERRNO);
        dperror("send");
        /* Keep connection alive, we'll try again next pass.

           Is this likely to catch any errors we didn't get from the
           select callbacks?  */
        return -1;
    }
    /* Yay, it worked.  */
    return 0;
}

static void
kill_conn(struct conn_state *conn, struct select_state *selstate, int err)
{
    dprint("abandoning connection %d: %m\n", conn->fd, err);
    cm_remove_fd(selstate, conn->fd);
    closesocket(conn->fd);
    conn->fd = INVALID_SOCKET;
    conn->state = FAILED;
    conn->err = err;
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
        dprint("getsockopt(SO_ERROR) on fd failed: %m\n", e);
        return e;
    }
    return sockerr;
}

/* Return nonzero only if we're finished and the caller should exit
   its loop.  This happens in two cases: We have a complete message,
   or the socket has closed and no others are open.  */

static int
service_tcp_fd(krb5_context context, struct conn_state *conn,
               struct select_state *selstate, int ssflags)
{
    int e = 0;
    ssize_t nwritten, nread;

    if (!(ssflags & (SSF_READ|SSF_WRITE|SSF_EXCEPTION)))
        abort();
    switch (conn->state) {
        SOCKET_WRITEV_TEMP tmp;

    case CONNECTING:
        if (ssflags & SSF_READ) {
            /* Bad -- the KDC shouldn't be sending to us first.  */
            e = EINVAL /* ?? */;
        kill_conn:
            TRACE_SENDTO_KDC_TCP_DISCONNECT(context, conn);
            kill_conn(conn, selstate, e);
            if (e == EINVAL) {
                closesocket(conn->fd);
                conn->fd = INVALID_SOCKET;
            }
            return e == 0;
        }
        if (ssflags & SSF_EXCEPTION) {
        handle_exception:
            e = get_so_error(conn->fd);
            if (e)
                dprint("socket error on exception fd: %m", e);
            else
                dprint("no socket error info available on exception fd");
            goto kill_conn;
        }

        /*
         * Connect finished -- but did it succeed or fail?
         * UNIX sets can_write if failed.
         * Call getsockopt to see if error pending.
         *
         * (For most UNIX systems it works to just try writing the
         * first time and detect an error.  But Bill Dodd at IBM
         * reports that some version of AIX, SIGPIPE can result.)
         */
        e = get_so_error(conn->fd);
        if (e) {
            TRACE_SENDTO_KDC_TCP_ERROR_CONNECT(context, conn, e);
            dprint("socket error on write fd: %m", e);
            goto kill_conn;
        }
        conn->state = WRITING;
        goto try_writing;

    case WRITING:
        if (ssflags & SSF_READ) {
            e = E2BIG;
            /* Bad -- the KDC shouldn't be sending anything yet.  */
            goto kill_conn;
        }
        if (ssflags & SSF_EXCEPTION)
            goto handle_exception;

    try_writing:
        dprint("trying to writev %d (%d bytes) to fd %d\n",
               conn->x.out.sg_count,
               ((conn->x.out.sg_count == 2 ? SG_LEN(&conn->x.out.sgp[1]) : 0)
                + SG_LEN(&conn->x.out.sgp[0])),
               conn->fd);
        TRACE_SENDTO_KDC_TCP_SEND(context, conn);
        nwritten = SOCKET_WRITEV(conn->fd, conn->x.out.sgp,
                                 conn->x.out.sg_count, tmp);
        if (nwritten < 0) {
            e = SOCKET_ERRNO;
            TRACE_SENDTO_KDC_TCP_ERROR_SEND(context, conn, e);
            dprint("failed: %m\n", e);
            goto kill_conn;
        }
        dprint("wrote %d bytes\n", nwritten);
        while (nwritten) {
            sg_buf *sgp = conn->x.out.sgp;
            if ((size_t) nwritten < SG_LEN(sgp)) {
                SG_ADVANCE(sgp, (size_t) nwritten);
                nwritten = 0;
            } else {
                nwritten -= SG_LEN(sgp);
                conn->x.out.sgp++;
                conn->x.out.sg_count--;
                if (conn->x.out.sg_count == 0 && nwritten != 0)
                    /* Wrote more than we wanted to?  */
                    abort();
            }
        }
        if (conn->x.out.sg_count == 0) {
            /* Done writing, switch to reading.  */
            /* Don't call shutdown at this point because
             * some implementations cannot deal with half-closed connections.*/
            cm_unset_write(selstate, conn->fd);
            /* Q: How do we detect failures to send the remaining data
               to the remote side, since we're in non-blocking mode?
               Will we always get errors on the reading side?  */
            dprint("switching fd %d to READING\n", conn->fd);
            conn->state = READING;
            conn->x.in.bufsizebytes_read = 0;
            conn->x.in.bufsize = 0;
            conn->x.in.buf = 0;
            conn->x.in.pos = 0;
            conn->x.in.n_left = 0;
        }
        return 0;

    case READING:
        if (ssflags & SSF_EXCEPTION) {
            if (conn->x.in.buf) {
                free(conn->x.in.buf);
                conn->x.in.buf = 0;
            }
            goto handle_exception;
        }

        if (conn->x.in.bufsizebytes_read == 4) {
            /* Reading data.  */
            dprint("reading %d bytes of data from fd %d\n",
                   (int) conn->x.in.n_left, conn->fd);
            nread = SOCKET_READ(conn->fd, conn->x.in.pos, conn->x.in.n_left);
            if (nread <= 0) {
                e = nread ? SOCKET_ERRNO : ECONNRESET;
                free(conn->x.in.buf);
                conn->x.in.buf = 0;
                TRACE_SENDTO_KDC_TCP_ERROR_RECV(context, conn, e);
                goto kill_conn;
            }
            conn->x.in.n_left -= nread;
            conn->x.in.pos += nread;
            if (conn->x.in.n_left <= 0) {
                /* We win!  */
                return 1;
            }
        } else {
            /* Reading length.  */
            nread = SOCKET_READ(conn->fd,
                                conn->x.in.bufsizebytes + conn->x.in.bufsizebytes_read,
                                4 - conn->x.in.bufsizebytes_read);
            if (nread < 0) {
                TRACE_SENDTO_KDC_TCP_ERROR_RECV_LEN(context, conn, e);
                e = SOCKET_ERRNO;
                goto kill_conn;
            }
            conn->x.in.bufsizebytes_read += nread;
            if (conn->x.in.bufsizebytes_read == 4) {
                unsigned long len = load_32_be (conn->x.in.bufsizebytes);
                dprint("received length on fd %d is %d\n", conn->fd, (int)len);
                /* Arbitrary 1M cap.  */
                if (len > 1 * 1024 * 1024) {
                    e = E2BIG;
                    goto kill_conn;
                }
                conn->x.in.bufsize = conn->x.in.n_left = len;
                conn->x.in.buf = conn->x.in.pos = malloc(len);
                dprint("allocated %d byte buffer at %p\n", (int) len,
                       conn->x.in.buf);
                if (conn->x.in.buf == 0) {
                    /* allocation failure */
                    e = ENOMEM;
                    goto kill_conn;
                }
            }
        }
        break;

    default:
        abort();
    }
    return 0;
}

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
        TRACE_SENDTO_KDC_UDP_ERROR_RECV(context, conn, SOCKET_ERRNO);
        kill_conn(conn, selstate, SOCKET_ERRNO);
        return 0;
    }
    conn->x.in.pos = conn->x.in.buf + nread;
    return 1;
}

static krb5_boolean
service_fds(krb5_context context, struct select_state *selstate, int interval,
            struct conn_state *conns, struct select_state *seltemp,
            int (*msg_handler)(krb5_context, const krb5_data *, void *),
            void *msg_handler_data, struct conn_state **winner_out)
{
    int e, selret = 0;
    struct timeval now;
    struct conn_state *state;

    *winner_out = NULL;

    e = k5_getcurtime(&now);
    if (e)
        return 1;
    selstate->end_time = now;
    selstate->end_time.tv_sec += interval;

    e = 0;
    while (selstate->nfds > 0) {
        e = cm_select_or_poll(selstate, seltemp, &selret);
        if (e == EINTR)
            continue;
        if (e != 0)
            break;

        dprint("service_fds examining results, selret=%d\n", selret);

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
                    dprint("fd service routine says we're done\n");
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
    int pass, delay;
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
            if (state->socktype != socktype1)
                continue;
            if (maybe_send(context, state, sel_state, callback_info))
                continue;
            done = service_fds(context, sel_state, 1, conns, seltemp,
                               msg_handler, msg_handler_data, &winner);
        }
    }

    /* Complete the first pass by contacting servers of the non-preferred
     * socktype (if given), waiting 1s for an answer from each. */
    for (state = conns; state != NULL && !done; state = state->next) {
        if (state->socktype != socktype2)
            continue;
        if (maybe_send(context, state, sel_state, callback_info))
            continue;
        done = service_fds(context, sel_state, 1, conns, seltemp, msg_handler,
                           msg_handler_data, &winner);
    }

    /* Wait for two seconds at the end of the first pass. */
    if (!done) {
        done = service_fds(context, sel_state, 2, conns, seltemp, msg_handler,
                           msg_handler_data, &winner);
    }

    /* Make remaining passes over all of the connections. */
    delay = 4;
    for (pass = 1; pass < MAX_PASS && !done; pass++) {
        for (state = conns; state != NULL && !done; state = state->next) {
            if (maybe_send(context, state, sel_state, callback_info))
                continue;
            done = service_fds(context, sel_state, 1, conns, seltemp,
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
    TRACE_SENDTO_KDC_RESPONSE(context, winner);
    reply->data = winner->x.in.buf;
    reply->length = winner->x.in.pos - winner->x.in.buf;
    retval = 0;
    winner->x.in.buf = NULL;
    if (server_used != NULL)
        *server_used = winner->server_index;
    if (remoteaddr != NULL && remoteaddrlen != 0 && *remoteaddrlen > 0)
        (void)getpeername(winner->fd, remoteaddr, remoteaddrlen);

cleanup:
    for (state = conns; state != NULL; state = next) {
        next = state->next;
        if (state->fd != INVALID_SOCKET)
            closesocket(state->fd);
        if (state->state == READING && state->x.in.buf != udpbuf)
            free(state->x.in.buf);
        if (callback_info) {
            callback_info->pfn_cleanup(callback_info->context,
                                       &state->callback_buffer);
        }
        free(state);
    }

    if (reply->data != udpbuf)
        free(udpbuf);
    free(sel_state);
    return retval;
}
