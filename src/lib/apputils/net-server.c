/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/apputils/net-server.c - Network code for krb5 servers (kdc, kadmind) */
/*
 * Copyright 1990,2000,2007,2008,2009,2010 by the Massachusetts Institute of Technology.
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

#include "k5-int.h"
#include "adm_proto.h"
#include <sys/ioctl.h>
#include <syslog.h>

#include <stddef.h>
#include "port-sockets.h"
#include "socket-utils.h"

#include <gssrpc/rpc.h>

#ifdef HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
/* for SIOCGIFCONF, etc. */
#include <sys/sockio.h>
#endif
#include <sys/time.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <arpa/inet.h>

#ifndef ARPHRD_ETHER /* OpenBSD breaks on multiple inclusions */
#include <net/if.h>
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>          /* FIONBIO */
#endif

#include "fake-addrinfo.h"
#include "net-server.h"
#include <signal.h>

/* XXX */
#define KDC5_NONET                               (-1779992062L)

static int tcp_or_rpc_data_counter;
static int max_tcp_or_rpc_data_connections = 45;

/* Misc utility routines.  */
static void
set_sa_port(struct sockaddr *addr, int port)
{
    switch (addr->sa_family) {
    case AF_INET:
        sa2sin(addr)->sin_port = port;
        break;
    case AF_INET6:
        sa2sin6(addr)->sin6_port = port;
        break;
    default:
        break;
    }
}

static int
ipv6_enabled()
{
    static int result = -1;
    if (result == -1) {
        int s;
        s = socket(AF_INET6, SOCK_STREAM, 0);
        if (s >= 0) {
            result = 1;
            close(s);
        } else
            result = 0;
    }
    return result;
}

static int
setreuseaddr(int sock, int value)
{
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
}

#if defined(IPV6_V6ONLY)
static int
setv6only(int sock, int value)
{
    return setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value));
}
#endif

/* Use RFC 3542 API below, but fall back from IPV6_RECVPKTINFO to
   IPV6_PKTINFO for RFC 2292 implementations.  */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif
/* Parallel, though not standardized.  */
#ifndef IP_RECVPKTINFO
#define IP_RECVPKTINFO IP_PKTINFO
#endif

static int
set_pktinfo(int sock, int family)
{
    int sockopt = 1;
    int option = 0, proto = 0;

    switch (family) {
#if defined(IP_PKTINFO) && defined(HAVE_STRUCT_IN_PKTINFO)
    case AF_INET:
        proto = IPPROTO_IP;
        option = IP_RECVPKTINFO;
        break;
#endif
#if defined(IPV6_PKTINFO) && defined(HAVE_STRUCT_IN6_PKTINFO)
    case AF_INET6:
        proto = IPPROTO_IPV6;
        option = IPV6_RECVPKTINFO;
        break;
#endif
    default:
        return EINVAL;
    }
    if (setsockopt(sock, proto, option, &sockopt, sizeof(sockopt)))
        return errno;
    return 0;
}


static const char *
paddr(struct sockaddr *sa)
{
    static char buf[100];
    char portbuf[10];
    if (getnameinfo(sa, socklen(sa),
                    buf, sizeof(buf), portbuf, sizeof(portbuf),
                    NI_NUMERICHOST|NI_NUMERICSERV))
        strlcpy(buf, "<unprintable>", sizeof(buf));
    else {
        unsigned int len = sizeof(buf) - strlen(buf);
        char *p = buf + strlen(buf);
        if (len > 2+strlen(portbuf)) {
            *p++ = '.';
            len--;
            strncpy(p, portbuf, len);
        }
    }
    return buf;
}

/* KDC data.  */

enum conn_type {
    CONN_UDP, CONN_UDP_PKTINFO, CONN_TCP_LISTENER, CONN_TCP,
    CONN_RPC_LISTENER, CONN_RPC,
    CONN_ROUTING
};

/* Per-connection info.  */
struct connection {
    void *handle;
    const char *prog;
    enum conn_type type;

    /* Connection fields (TCP or RPC) */
    struct sockaddr_storage addr_s;
    socklen_t addrlen;
    char addrbuf[56];
    krb5_fulladdr faddr;
    krb5_address kaddr;

    /* Incoming data (TCP) */
    size_t bufsiz;
    size_t offset;
    char *buffer;
    size_t msglen;

    /* Outgoing data (TCP) */
    krb5_data *response;
    unsigned char lenbuf[4];
    sg_buf sgbuf[2];
    sg_buf *sgp;
    int sgnum;

    /* Crude denial-of-service avoidance support (TCP or RPC) */
    time_t start_time;

    /* RPC-specific fields */
    SVCXPRT *transp;
    int rpc_force_close;
};


#define SET(TYPE) struct { TYPE *data; size_t n, max; }

/* Start at the top and work down -- this should allow for deletions
   without disrupting the iteration, since we delete by overwriting
   the element to be removed with the last element.  */
#define FOREACH_ELT(set,idx,vvar)                                       \
    for (idx = set.n-1; idx >= 0 && (vvar = set.data[idx], 1); idx--)

#define GROW_SET(set, incr, tmpptr)                                     \
    ((set.max + incr < set.max                                          \
      || ((set.max + incr) * sizeof(set.data[0]) / sizeof(set.data[0])  \
          != set.max + incr))                                           \
     ? 0                         /* overflow */                         \
     : ((tmpptr = realloc(set.data,                                     \
                          (set.max + incr) * sizeof(set.data[0])))      \
        ? (set.data = tmpptr, set.max += incr, 1)                       \
        : 0))

/* 1 = success, 0 = failure */
#define ADD(set, val, tmpptr)                           \
    ((set.n < set.max || GROW_SET(set, 10, tmpptr))     \
     ? (set.data[set.n++] = val, 1)                     \
     : 0)

#define DEL(set, idx)                           \
    (set.data[idx] = set.data[--set.n], 0)

#define FREE_SET_DATA(set)                                      \
    (free(set.data), set.data = 0, set.max = 0, set.n = 0)

/*
 * N.B.: The Emacs cc-mode indentation code seems to get confused if
 * the macro argument here is one word only.  So use "unsigned short"
 * instead of the "u_short" we were using before.
 */
struct rpc_svc_data {
    u_short port;
    u_long prognum;
    u_long versnum;
    void (*dispatch)();
};
static SET(unsigned short) udp_port_data, tcp_port_data;
static SET(struct rpc_svc_data) rpc_svc_data;
static SET(verto_ev *) events;

verto_ctx *
loop_init(verto_ev_type types)
{
    types |= VERTO_EV_TYPE_IO;
    types |= VERTO_EV_TYPE_SIGNAL;
    types |= VERTO_EV_TYPE_TIMEOUT;
    return verto_default(NULL, types);
}

static void
do_break(verto_ctx *ctx, verto_ev *ev)
{
    krb5_klog_syslog(LOG_DEBUG, _("Got signal to request exit"));
    verto_break(ctx);
}

struct sighup_context {
    void *handle;
    void (*reset)(void *);
};

static void
do_reset(verto_ctx *ctx, verto_ev *ev)
{
    struct sighup_context *sc = (struct sighup_context*) verto_get_private(ev);

    krb5_klog_syslog(LOG_DEBUG, _("Got signal to reset"));
    krb5_klog_reopen(get_context(sc->handle));
    if (sc->reset)
        sc->reset(sc->handle);
}

static void
free_sighup_context(verto_ctx *ctx, verto_ev *ev)
{
    free(verto_get_private(ev));
}

krb5_error_code
loop_setup_signals(verto_ctx *ctx, void *handle, void (*reset)())
{
    struct sighup_context *sc;
    verto_ev *ev;

    if (!verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, do_break, SIGINT)  ||
        !verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, do_break, SIGTERM) ||
        !verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, do_break, SIGQUIT) ||
        !verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, VERTO_SIG_IGN, SIGPIPE))
        return ENOMEM;

    ev = verto_add_signal(ctx, VERTO_EV_FLAG_PERSIST, do_reset, SIGHUP);
    if (!ev)
        return ENOMEM;

    sc = malloc(sizeof(*sc));
    if (!sc)
        return ENOMEM;

    sc->handle = handle;
    sc->reset = reset;
    verto_set_private(ev, sc, free_sighup_context);
    return 0;
}

krb5_error_code
loop_add_udp_port(int port)
{
    int i;
    void *tmp;
    u_short val;
    u_short s_port = port;

    if (s_port != port)
        return EINVAL;

    FOREACH_ELT (udp_port_data, i, val)
        if (s_port == val)
            return 0;
    if (!ADD(udp_port_data, s_port, tmp))
        return ENOMEM;
    return 0;
}

krb5_error_code
loop_add_tcp_port(int port)
{
    int i;
    void *tmp;
    u_short val;
    u_short s_port = port;

    if (s_port != port)
        return EINVAL;

    FOREACH_ELT (tcp_port_data, i, val)
        if (s_port == val)
            return 0;
    if (!ADD(tcp_port_data, s_port, tmp))
        return ENOMEM;
    return 0;
}

krb5_error_code
loop_add_rpc_service(int port, u_long prognum,
                     u_long versnum, void (*dispatchfn)())
{
    int i;
    void *tmp;
    struct rpc_svc_data svc, val;

    svc.port = port;
    if (svc.port != port)
        return EINVAL;
    svc.prognum = prognum;
    svc.versnum = versnum;
    svc.dispatch = dispatchfn;

    FOREACH_ELT (rpc_svc_data, i, val) {
        if (val.port == port)
            return 0;
    }
    if (!ADD(rpc_svc_data, svc, tmp))
        return ENOMEM;
    return 0;
}


#define USE_AF AF_INET
#define USE_TYPE SOCK_DGRAM
#define USE_PROTO 0
#define SOCKET_ERRNO errno
#include "foreachaddr.h"

struct socksetup {
    verto_ctx *ctx;
    void *handle;
    const char *prog;
    krb5_error_code retval;
    int udp_flags;
#define UDP_DO_IPV4 1
#define UDP_DO_IPV6 2
};

static void
free_connection(struct connection *conn)
{
    if (!conn)
        return;
    if (conn->response)
        krb5_free_data(get_context(conn->handle), conn->response);
    if (conn->buffer)
        free(conn->buffer);
    if (conn->type == CONN_RPC_LISTENER && conn->transp != NULL)
        svc_destroy(conn->transp);
    free(conn);
}

static void
remove_event_from_set(verto_ev *ev)
{
    verto_ev *tmp;
    int i;

    /* Remove the event from the events. */
    FOREACH_ELT(events, i, tmp)
        if (tmp == ev) {
            DEL(events, i);
            break;
        }
}

static void
free_socket(verto_ctx *ctx, verto_ev *ev)
{
    struct connection *conn = NULL;
    fd_set fds;
    int fd;

    remove_event_from_set(ev);

    fd = verto_get_fd(ev);
    conn = verto_get_private(ev);

    /* Close the file descriptor. */
    krb5_klog_syslog(LOG_INFO, _("closing down fd %d"), fd);
    if (fd >= 0 && (!conn || conn->type != CONN_RPC || conn->rpc_force_close))
        close(fd);

    /* Free the connection struct. */
    if (conn) {
        switch (conn->type) {
        case CONN_RPC:
            if (conn->rpc_force_close) {
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                svc_getreqset(&fds);
                if (FD_ISSET(fd, &svc_fdset)) {
                    krb5_klog_syslog(LOG_ERR,
                                     _("descriptor %d closed but still "
                                       "in svc_fdset"),
                                     fd);
                }
            }
            /* Fall through. */
        case CONN_TCP:
            tcp_or_rpc_data_counter--;
            break;
        default:
            break;
        }

        free_connection(conn);
    }
}

static verto_ev *
make_event(verto_ctx *ctx, verto_ev_flag flags, verto_callback callback,
           int sock, struct connection *conn, int addevent)
{
    verto_ev *ev;
    void *tmp;

    ev = verto_add_io(ctx, flags, callback, sock);
    if (!ev) {
        com_err(conn->prog, ENOMEM, _("cannot create io event"));
        return NULL;
    }

    if (addevent) {
        if (!ADD(events, ev, tmp)) {
            com_err(conn->prog, ENOMEM, _("cannot save event"));
            verto_del(ev);
            return NULL;
        }
    }

    verto_set_private(ev, conn, free_socket);
    return ev;
}

static verto_ev *
add_fd(struct socksetup *data, int sock, enum conn_type conntype,
       verto_ev_flag flags, verto_callback callback, int addevent)
{
    struct connection *newconn;

#ifndef _WIN32
    if (sock >= FD_SETSIZE) {
        data->retval = EMFILE;  /* XXX */
        com_err(data->prog, 0,
                _("file descriptor number %d too high"), sock);
        return 0;
    }
#endif
    newconn = malloc(sizeof(*newconn));
    if (newconn == NULL) {
        data->retval = ENOMEM;
        com_err(data->prog, ENOMEM,
                _("cannot allocate storage for connection info"));
        return 0;
    }
    memset(newconn, 0, sizeof(*newconn));
    newconn->handle = data->handle;
    newconn->prog = data->prog;
    newconn->type = conntype;

    return make_event(data->ctx, flags, callback, sock, newconn, addevent);
}

static void process_packet(verto_ctx *ctx, verto_ev *ev);
static void accept_tcp_connection(verto_ctx *ctx, verto_ev *ev);
static void process_tcp_connection_read(verto_ctx *ctx, verto_ev *ev);
static void process_tcp_connection_write(verto_ctx *ctx, verto_ev *ev);
static void accept_rpc_connection(verto_ctx *ctx, verto_ev *ev);
static void process_rpc_connection(verto_ctx *ctx, verto_ev *ev);

static verto_ev *
add_udp_fd(struct socksetup *data, int sock, int pktinfo)
{
    return add_fd(data, sock, pktinfo ? CONN_UDP_PKTINFO : CONN_UDP,
                  VERTO_EV_FLAG_IO_READ |
                  VERTO_EV_FLAG_PERSIST |
                  VERTO_EV_FLAG_REINITIABLE,
                  process_packet, 1);
}

static verto_ev *
add_tcp_listener_fd(struct socksetup *data, int sock)
{
    return add_fd(data, sock, CONN_TCP_LISTENER,
                  VERTO_EV_FLAG_IO_READ |
                  VERTO_EV_FLAG_PERSIST |
                  VERTO_EV_FLAG_REINITIABLE,
                  accept_tcp_connection, 1);
}

static verto_ev *
add_tcp_read_fd(struct socksetup *data, int sock)
{
    return add_fd(data, sock, CONN_TCP,
                  VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_PERSIST,
                  process_tcp_connection_read, 1);
}

/*
 * Create a socket and bind it to addr.  Ensure the socket will work with
 * select().  Set the socket cloexec, reuseaddr, and if applicable v6-only.
 * Does not call listen().  Returns -1 on failure after logging an error.
 */
static int
create_server_socket(struct socksetup *data, struct sockaddr *addr, int type)
{
    int sock;

    sock = socket(addr->sa_family, type, 0);
    if (sock == -1) {
        data->retval = errno;
        com_err(data->prog, errno, _("Cannot create TCP server socket on %s"),
                paddr(addr));
        return -1;
    }
    set_cloexec_fd(sock);

#ifndef _WIN32                  /* Windows FD_SETSIZE is a count. */
    if (sock >= FD_SETSIZE) {
        close(sock);
        com_err(data->prog, 0, _("TCP socket fd number %d (for %s) too high"),
                sock, paddr(addr));
        return -1;
    }
#endif

    if (setreuseaddr(sock, 1) < 0) {
        com_err(data->prog, errno,
                _("Cannot enable SO_REUSEADDR on fd %d"), sock);
    }

    if (addr->sa_family == AF_INET6) {
#ifdef IPV6_V6ONLY
        if (setv6only(sock, 1))
            com_err(data->prog, errno,
                    _("setsockopt(%d,IPV6_V6ONLY,1) failed"), sock);
        else
            com_err(data->prog, 0, _("setsockopt(%d,IPV6_V6ONLY,1) worked"),
                    sock);
#else
        krb5_klog_syslog(LOG_INFO, _("no IPV6_V6ONLY socket option support"));
#endif /* IPV6_V6ONLY */
    }

    if (bind(sock, addr, socklen(addr)) == -1) {
        data->retval = errno;
        com_err(data->prog, errno, _("Cannot bind server socket on %s"),
                paddr(addr));
        close(sock);
        return -1;
    }

    return sock;
}

static verto_ev *
add_rpc_listener_fd(struct socksetup *data, struct rpc_svc_data *svc, int sock)
{
    struct connection *conn;
    verto_ev *ev;

    ev = add_fd(data, sock, CONN_RPC_LISTENER,
                VERTO_EV_FLAG_IO_READ |
                VERTO_EV_FLAG_PERSIST |
                VERTO_EV_FLAG_REINITIABLE,
                accept_rpc_connection, 1);
    if (ev == NULL)
        return NULL;

    conn = verto_get_private(ev);
    conn->transp = svctcp_create(sock, 0, 0);
    if (conn->transp == NULL) {
        krb5_klog_syslog(LOG_ERR,
                         _("Cannot create RPC service: %s; continuing"),
                         strerror(errno));
        verto_del(ev);
        return NULL;
    }

    if (!svc_register(conn->transp, svc->prognum, svc->versnum,
                      svc->dispatch, 0)) {
        krb5_klog_syslog(LOG_ERR,
                         _("Cannot register RPC service: %s; continuing"),
                         strerror(errno));
        verto_del(ev);
        return NULL;
    }

    return ev;
}

static verto_ev *
add_rpc_data_fd(struct socksetup *data, int sock)
{
    return add_fd(data, sock, CONN_RPC,
                  VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_PERSIST,
                  process_rpc_connection, 1);
}

static const int one = 1;

static int
setnbio(int sock)
{
    return ioctlsocket(sock, FIONBIO, (const void *)&one);
}

static int
setkeepalive(int sock)
{
    return setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
}

static int
setnolinger(int s)
{
    static const struct linger ling = { 0, 0 };
    return setsockopt(s, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
}

/* Returns -1 or socket fd.  */
static int
setup_a_tcp_listener(struct socksetup *data, struct sockaddr *addr)
{
    int sock;

    sock = create_server_socket(data, addr, SOCK_STREAM);
    if (sock == -1)
        return -1;
    if (listen(sock, 5) < 0) {
        com_err(data->prog, errno,
                _("Cannot listen on TCP server socket on %s"), paddr(addr));
        close(sock);
        return -1;
    }
    if (setnbio(sock)) {
        com_err(data->prog, errno,
                _("cannot set listening tcp socket on %s non-blocking"),
                paddr(addr));
        close(sock);
        return -1;
    }
    if (setnolinger(sock)) {
        com_err(data->prog, errno,
                _("disabling SO_LINGER on TCP socket on %s"), paddr(addr));
        close(sock);
        return -1;
    }
    return sock;
}

static int
setup_tcp_listener_ports(struct socksetup *data)
{
    struct sockaddr_in sin4;
    struct sockaddr_in6 sin6;
    int i, port;

    memset(&sin4, 0, sizeof(sin4));
    sin4.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
    sin4.sin_len = sizeof(sin4);
#endif
    sin4.sin_addr.s_addr = INADDR_ANY;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
    sin6.sin6_len = sizeof(sin6);
#endif
    sin6.sin6_addr = in6addr_any;

    FOREACH_ELT (tcp_port_data, i, port) {
        int s4, s6;

        set_sa_port((struct sockaddr *)&sin4, htons(port));
        if (!ipv6_enabled()) {
            s4 = setup_a_tcp_listener(data, (struct sockaddr *)&sin4);
            if (s4 < 0)
                return -1;
            s6 = -1;
        } else {
            s4 = s6 = -1;

            set_sa_port((struct sockaddr *)&sin6, htons(port));

            s6 = setup_a_tcp_listener(data, (struct sockaddr *)&sin6);
            if (s6 < 0)
                return -1;

            s4 = setup_a_tcp_listener(data, (struct sockaddr *)&sin4);
        }

        /* Sockets are created, prepare to listen on them. */
        if (s4 >= 0) {
            if (add_tcp_listener_fd(data, s4) == NULL)
                close(s4);
            else {
                krb5_klog_syslog(LOG_INFO, _("listening on fd %d: tcp %s"),
                                 s4, paddr((struct sockaddr *)&sin4));
            }
        }
        if (s6 >= 0) {
            if (add_tcp_listener_fd(data, s6) == NULL) {
                close(s6);
                s6 = -1;
            } else {
                krb5_klog_syslog(LOG_INFO, _("listening on fd %d: tcp %s"),
                                 s6, paddr((struct sockaddr *)&sin6));
            }
            if (s4 < 0)
                krb5_klog_syslog(LOG_INFO,
                                 _("assuming IPv6 socket accepts IPv4"));
        }
    }
    return 0;
}

static int
setup_rpc_listener_ports(struct socksetup *data)
{
    struct sockaddr_in sin4;
    struct sockaddr_in6 sin6;
    int i;
    struct rpc_svc_data svc;

    memset(&sin4, 0, sizeof(sin4));
    sin4.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
    sin4.sin_len = sizeof(sin4);
#endif
    sin4.sin_addr.s_addr = INADDR_ANY;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
    sin6.sin6_len = sizeof(sin6);
#endif
    sin6.sin6_addr = in6addr_any;

    FOREACH_ELT (rpc_svc_data, i, svc) {
        int s4;
        int s6;

        set_sa_port((struct sockaddr *)&sin4, htons(svc.port));
        s4 = create_server_socket(data, (struct sockaddr *)&sin4, SOCK_STREAM);
        if (s4 < 0)
            return -1;

        if (add_rpc_listener_fd(data, &svc, s4) == NULL)
            close(s4);
        else
            krb5_klog_syslog(LOG_INFO, _("listening on fd %d: rpc %s"),
                             s4, paddr((struct sockaddr *)&sin4));

        if (ipv6_enabled()) {
            set_sa_port((struct sockaddr *)&sin6, htons(svc.port));
            s6 = create_server_socket(data, (struct sockaddr *)&sin6,
                                      SOCK_STREAM);
            if (s6 < 0)
                return -1;

            if (add_rpc_listener_fd(data, &svc, s6) == NULL)
                close(s6);
            else
                krb5_klog_syslog(LOG_INFO, _("listening on fd %d: rpc %s"),
                                 s6, paddr((struct sockaddr *)&sin6));
        }
    }

    return 0;
}

#if defined(CMSG_SPACE) && defined(HAVE_STRUCT_CMSGHDR) &&      \
    (defined(IP_PKTINFO) || defined(IPV6_PKTINFO))
union pktinfo {
#ifdef HAVE_STRUCT_IN6_PKTINFO
    struct in6_pktinfo pi6;
#endif
#ifdef HAVE_STRUCT_IN_PKTINFO
    struct in_pktinfo pi4;
#endif
    char c;
};

static int
setup_udp_port_1(struct socksetup *data, struct sockaddr *addr,
                 char *haddrbuf, int pktinfo);

static void
setup_udp_pktinfo_ports(struct socksetup *data)
{
#ifdef IP_PKTINFO
    {
        struct sockaddr_in sa;
        int r;

        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
        sa.sin_len = sizeof(sa);
#endif
        r = setup_udp_port_1(data, (struct sockaddr *) &sa, "0.0.0.0", 4);
        if (r == 0)
            data->udp_flags &= ~UDP_DO_IPV4;
    }
#endif
#ifdef IPV6_PKTINFO
    {
        struct sockaddr_in6 sa;
        int r;

        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
        sa.sin6_len = sizeof(sa);
#endif
        r = setup_udp_port_1(data, (struct sockaddr *) &sa, "::", 6);
        if (r == 0)
            data->udp_flags &= ~UDP_DO_IPV6;
    }
#endif
}
#else /* no pktinfo compile-time support */
static void
setup_udp_pktinfo_ports(struct socksetup *data)
{
}
#endif

static int
setup_udp_port_1(struct socksetup *data, struct sockaddr *addr,
                 char *haddrbuf, int pktinfo)
{
    int sock = -1, i, r;
    u_short port;

    FOREACH_ELT (udp_port_data, i, port) {
        set_sa_port(addr, htons(port));
        sock = create_server_socket(data, addr, SOCK_DGRAM);
        if (sock == -1)
            return 1;
        setnbio(sock);

#if !(defined(CMSG_SPACE) && defined(HAVE_STRUCT_CMSGHDR) &&    \
      (defined(IP_PKTINFO) || defined(IPV6_PKTINFO)))
        assert(pktinfo == 0);
#endif
        if (pktinfo) {
            r = set_pktinfo(sock, addr->sa_family);
            if (r) {
                com_err(data->prog, r,
                        _("Cannot request packet info for udp socket address "
                          "%s port %d"), haddrbuf, port);
                close(sock);
                return 1;
            }
        }
        krb5_klog_syslog(LOG_INFO, _("listening on fd %d: udp %s%s"), sock,
                         paddr((struct sockaddr *)addr),
                         pktinfo ? " (pktinfo)" : "");
        if (add_udp_fd (data, sock, pktinfo) == 0) {
            close(sock);
            return 1;
        }
    }
    return 0;
}

static int
setup_udp_port(void *P_data, struct sockaddr *addr)
{
    struct socksetup *data = P_data;
    char haddrbuf[NI_MAXHOST];
    int err;

    if (addr->sa_family == AF_INET && !(data->udp_flags & UDP_DO_IPV4))
        return 0;
#ifdef AF_INET6
    if (addr->sa_family == AF_INET6 && !(data->udp_flags & UDP_DO_IPV6))
        return 0;
#endif
    err = getnameinfo(addr, socklen(addr), haddrbuf, sizeof(haddrbuf),
                      0, 0, NI_NUMERICHOST);
    if (err)
        strlcpy(haddrbuf, "<unprintable>", sizeof(haddrbuf));

    switch (addr->sa_family) {
    case AF_INET:
        break;
#ifdef AF_INET6
    case AF_INET6:
        break;
#endif
#ifdef AF_LINK /* some BSD systems, AIX */
    case AF_LINK:
        return 0;
#endif
#ifdef AF_DLI /* Direct Link Interface - DEC Ultrix/OSF1 link layer? */
    case AF_DLI:
        return 0;
#endif
#ifdef AF_APPLETALK
    case AF_APPLETALK:
        return 0;
#endif
    default:
        krb5_klog_syslog(LOG_INFO,
                         _("skipping unrecognized local address family %d"),
                         addr->sa_family);
        return 0;
    }
    return setup_udp_port_1(data, addr, haddrbuf, 0);
}

#if 1
static void
klog_handler(const void *data, size_t len)
{
    static char buf[BUFSIZ];
    static int bufoffset;
    void *p;

#define flush_buf()                             \
    (bufoffset                                  \
     ? (((buf[0] == 0 || buf[0] == '\n')        \
         ? (fork()==0?abort():(void)0)          \
         : (void)0),                            \
        krb5_klog_syslog(LOG_INFO, "%s", buf),  \
        memset(buf, 0, sizeof(buf)),            \
        bufoffset = 0)                          \
     : 0)

    p = memchr(data, 0, len);
    if (p)
        len = (const char *)p - (const char *)data;
scan_for_newlines:
    if (len == 0)
        return;
    p = memchr(data, '\n', len);
    if (p) {
        if (p != data)
            klog_handler(data, (size_t)((const char *)p - (const char *)data));
        flush_buf();
        len -= ((const char *)p - (const char *)data) + 1;
        data = 1 + (const char *)p;
        goto scan_for_newlines;
    } else if (len > sizeof(buf) - 1 || len + bufoffset > sizeof(buf) - 1) {
        size_t x = sizeof(buf) - len - 1;
        klog_handler(data, x);
        flush_buf();
        len -= x;
        data = (const char *)data + x;
        goto scan_for_newlines;
    } else {
        memcpy(buf + bufoffset, data, len);
        bufoffset += len;
    }
}
#endif

#ifdef HAVE_STRUCT_RT_MSGHDR
#include <net/route.h>

static char *
rtm_type_name(int type)
{
    switch (type) {
    case RTM_ADD: return "RTM_ADD";
    case RTM_DELETE: return "RTM_DELETE";
    case RTM_NEWADDR: return "RTM_NEWADDR";
    case RTM_DELADDR: return "RTM_DELADDR";
    case RTM_IFINFO: return "RTM_IFINFO";
    case RTM_OLDADD: return "RTM_OLDADD";
    case RTM_OLDDEL: return "RTM_OLDDEL";
    case RTM_RESOLVE: return "RTM_RESOLVE";
#ifdef RTM_NEWMADDR
    case RTM_NEWMADDR: return "RTM_NEWMADDR";
    case RTM_DELMADDR: return "RTM_DELMADDR";
#endif
    case RTM_MISS: return "RTM_MISS";
    case RTM_REDIRECT: return "RTM_REDIRECT";
    case RTM_LOSING: return "RTM_LOSING";
    case RTM_GET: return "RTM_GET";
    default: return "?";
    }
}

static void
do_network_reconfig(verto_ctx *ctx, verto_ev *ev)
{
    struct connection *conn = verto_get_private(ev);
    if (loop_setup_network(ctx, conn->handle, conn->prog) != 0) {
        krb5_klog_syslog(LOG_ERR, _("Failed to reconfigure network, exiting"));
        verto_break(ctx);
    }
}

static int
routing_update_needed(struct rt_msghdr *rtm)
{
    switch (rtm->rtm_type) {
    case RTM_ADD:
    case RTM_DELETE:
    case RTM_NEWADDR:
    case RTM_DELADDR:
    case RTM_IFINFO:
    case RTM_OLDADD:
    case RTM_OLDDEL:
        /*
         * Some flags indicate routing table updates that don't
         * indicate local address changes.  They may come from
         * redirects, or ARP, etc.
         *
         * This set of symbols is just an initial guess based on
         * some messages observed in real life; working out which
         * other flags also indicate messages we should ignore,
         * and which flags are portable to all system and thus
         * don't need to be conditionalized, is left as a future
         * exercise.
         */
#ifdef RTF_DYNAMIC
        if (rtm->rtm_flags & RTF_DYNAMIC)
            break;
#endif
#ifdef RTF_CLONED
        if (rtm->rtm_flags & RTF_CLONED)
            break;
#endif
#ifdef RTF_LLINFO
        if (rtm->rtm_flags & RTF_LLINFO)
            break;
#endif
#if 0
        krb5_klog_syslog(LOG_DEBUG,
                         "network reconfiguration message (%s) received",
                         rtm_type_name(rtm->rtm_type));
#endif
        return 1;
    case RTM_RESOLVE:
#ifdef RTM_NEWMADDR
    case RTM_NEWMADDR:
    case RTM_DELMADDR:
#endif
    case RTM_MISS:
    case RTM_REDIRECT:
    case RTM_LOSING:
    case RTM_GET:
        /* Not interesting.  */
#if 0
        krb5_klog_syslog(LOG_DEBUG, "routing msg not interesting");
#endif
        break;
    default:
        krb5_klog_syslog(LOG_INFO,
                         _("unhandled routing message type %d, "
                           "will reconfigure just for the fun of it"),
                         rtm->rtm_type);
        return 1;
    }

    return 0;
}

static void
process_routing_update(verto_ctx *ctx, verto_ev *ev)
{
    int fd;
    ssize_t n_read;
    size_t sz_read;
    struct rt_msghdr rtm;
    struct connection *conn;

    fd = verto_get_fd(ev);
    conn = verto_get_private(ev);
    while ((n_read = read(fd, &rtm, sizeof(rtm))) > 0) {
        sz_read = (size_t) n_read; /* Safe, since we just checked the sign */
        if (sz_read < sizeof(rtm)) {
            /* Quick hack to figure out if the interesting
               fields are present in a short read.

               A short read seems to be normal for some message types.
               Only complain if we don't have the critical initial
               header fields.  */
#define RS(FIELD) (offsetof(struct rt_msghdr, FIELD) + sizeof(rtm.FIELD))
            if (sz_read < RS(rtm_type) ||
                sz_read < RS(rtm_version) ||
                sz_read < RS(rtm_msglen)) {
                krb5_klog_syslog(LOG_ERR,
                                 _("short read (%d/%d) from routing socket"),
                                 (int)sz_read, (int) sizeof(rtm));
                return;
            }
        }
#if 0
        krb5_klog_syslog(LOG_INFO,
                         _("got routing msg type %d(%s) v%d"),
                         rtm.rtm_type, rtm_type_name(rtm.rtm_type),
                         rtm.rtm_version);
#endif
        if (rtm.rtm_msglen > sizeof(rtm)) {
            /* It appears we get a partial message and the rest is
               thrown away?  */
        } else if (rtm.rtm_msglen != sz_read) {
            krb5_klog_syslog(LOG_ERR,
                             _("read %d from routing socket but msglen is %d"),
                             (int)sz_read, rtm.rtm_msglen);
        }

        if (routing_update_needed(&rtm)) {
            /* Ideally we would use idle here instead of timeout. However, idle
             * is not universally supported yet in all backends. So let's just
             * use timeout for now to avoid locking into a loop. */
            ev = verto_add_timeout(ctx, VERTO_EV_FLAG_NONE,
                                   do_network_reconfig, 0);
            verto_set_private(ev, conn, NULL);
            assert(ev);
        }
    }
}
#endif

krb5_error_code
loop_setup_routing_socket(verto_ctx *ctx, void *handle, const char *progname)
{
#ifdef HAVE_STRUCT_RT_MSGHDR
    struct socksetup data;
    int sock;

    data.ctx = ctx;
    data.handle = handle;
    data.prog = progname;
    data.retval = 0;

    sock = socket(PF_ROUTE, SOCK_RAW, 0);
    if (sock < 0) {
        int e = errno;
        krb5_klog_syslog(LOG_INFO, _("couldn't set up routing socket: %s"),
                         strerror(e));
    } else {
        krb5_klog_syslog(LOG_INFO, _("routing socket is fd %d"), sock);
        setnbio(sock);
        add_fd(&data, sock, CONN_ROUTING,
               VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_PERSIST,
               process_routing_update, 0);
    }
#endif
    return 0;
}

/* XXX */
extern void (*krb5int_sendtokdc_debug_handler)(const void*, size_t);

krb5_error_code
loop_setup_network(verto_ctx *ctx, void *handle, const char *prog)
{
    struct socksetup setup_data;
    verto_ev *ev;
    int i;

    krb5int_sendtokdc_debug_handler = klog_handler;

    /* Close any open connections. */
    FOREACH_ELT(events, i, ev)
        verto_del(ev);
    events.n = 0;

    setup_data.ctx = ctx;
    setup_data.handle = handle;
    setup_data.prog = prog;
    setup_data.retval = 0;
    krb5_klog_syslog(LOG_INFO, _("setting up network..."));

    /*
     * To do: Use RFC 2292 interface (or follow-on) and IPV6_PKTINFO,
     * so we might need only one UDP socket; fall back to binding
     * sockets on each address only if IPV6_PKTINFO isn't
     * supported.
     */
    setup_data.udp_flags = UDP_DO_IPV4 | UDP_DO_IPV6;
    setup_udp_pktinfo_ports(&setup_data);
    if (setup_data.udp_flags) {
        if (foreach_localaddr (&setup_data, setup_udp_port, 0, 0)) {
            return setup_data.retval;
        }
    }
    setup_tcp_listener_ports(&setup_data);
    setup_rpc_listener_ports(&setup_data);
    krb5_klog_syslog (LOG_INFO, _("set up %d sockets"), (int) events.n);
    if (events.n == 0) {
        com_err(prog, 0, _("no sockets set up?"));
        exit (1);
    }

    return 0;
}

void
init_addr(krb5_fulladdr *faddr, struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        faddr->address->addrtype = ADDRTYPE_INET;
        faddr->address->length = 4;
        faddr->address->contents = (krb5_octet *) &sa2sin(sa)->sin_addr;
        faddr->port = ntohs(sa2sin(sa)->sin_port);
        break;
    case AF_INET6:
        if (IN6_IS_ADDR_V4MAPPED(&sa2sin6(sa)->sin6_addr)) {
            faddr->address->addrtype = ADDRTYPE_INET;
            faddr->address->length = 4;
            faddr->address->contents = 12 + (krb5_octet *) &sa2sin6(sa)->sin6_addr;
        } else {
            faddr->address->addrtype = ADDRTYPE_INET6;
            faddr->address->length = 16;
            faddr->address->contents = (krb5_octet *) &sa2sin6(sa)->sin6_addr;
        }
        faddr->port = ntohs(sa2sin6(sa)->sin6_port);
        break;
    default:
        faddr->address->addrtype = -1;
        faddr->address->length = 0;
        faddr->address->contents = 0;
        faddr->port = 0;
        break;
    }
}

/*
 * This holds whatever additional information might be needed to
 * properly send back to the client from the correct local address.
 *
 * In this case, we only need one datum so far: On Mac OS X, the
 * kernel doesn't seem to like sending from link-local addresses
 * unless we specify the correct interface.
 */

union aux_addressing_info {
    int ipv6_ifindex;
};

static int
recv_from_to(int s, void *buf, size_t len, int flags,
             struct sockaddr *from, socklen_t *fromlen,
             struct sockaddr *to, socklen_t *tolen,
             union aux_addressing_info *auxaddr)
{
#if (!defined(IP_PKTINFO) && !defined(IPV6_PKTINFO)) || !defined(CMSG_SPACE)
    if (to && tolen) {
        /* Clobber with something recognizeable in case we try to use
           the address.  */
        memset(to, 0x40, *tolen);
        *tolen = 0;
    }

    return recvfrom(s, buf, len, flags, from, fromlen);
#else
    int r;
    struct iovec iov;
    char cmsg[CMSG_SPACE(sizeof(union pktinfo))];
    struct cmsghdr *cmsgptr;
    struct msghdr msg;

    if (!to || !tolen)
        return recvfrom(s, buf, len, flags, from, fromlen);

    /* Clobber with something recognizeable in case we can't extract
       the address but try to use it anyways.  */
    memset(to, 0x40, *tolen);

    iov.iov_base = buf;
    iov.iov_len = len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = from;
    msg.msg_namelen = *fromlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = sizeof(cmsg);

    r = recvmsg(s, &msg, flags);
    if (r < 0)
        return r;
    *fromlen = msg.msg_namelen;

    /* On Darwin (and presumably all *BSD with KAME stacks),
       CMSG_FIRSTHDR doesn't check for a non-zero controllen.  RFC
       3542 recommends making this check, even though the (new) spec
       for CMSG_FIRSTHDR says it's supposed to do the check.  */
    if (msg.msg_controllen) {
        cmsgptr = CMSG_FIRSTHDR(&msg);
        while (cmsgptr) {
#ifdef IP_PKTINFO
            if (cmsgptr->cmsg_level == IPPROTO_IP
                && cmsgptr->cmsg_type == IP_PKTINFO
                && *tolen >= sizeof(struct sockaddr_in)) {
                struct in_pktinfo *pktinfo;
                memset(to, 0, sizeof(struct sockaddr_in));
                pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsgptr);
                ((struct sockaddr_in *)to)->sin_addr = pktinfo->ipi_addr;
                ((struct sockaddr_in *)to)->sin_family = AF_INET;
                *tolen = sizeof(struct sockaddr_in);
                return r;
            }
#endif
#if defined(IPV6_PKTINFO) && defined(HAVE_STRUCT_IN6_PKTINFO)
            if (cmsgptr->cmsg_level == IPPROTO_IPV6
                && cmsgptr->cmsg_type == IPV6_PKTINFO
                && *tolen >= sizeof(struct sockaddr_in6)) {
                struct in6_pktinfo *pktinfo;
                memset(to, 0, sizeof(struct sockaddr_in6));
                pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
                ((struct sockaddr_in6 *)to)->sin6_addr = pktinfo->ipi6_addr;
                ((struct sockaddr_in6 *)to)->sin6_family = AF_INET6;
                *tolen = sizeof(struct sockaddr_in6);
                auxaddr->ipv6_ifindex = pktinfo->ipi6_ifindex;
                return r;
            }
#endif
            cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
        }
    }
    /* No info about destination addr was available.  */
    *tolen = 0;
    return r;
#endif
}

static int
send_to_from(int s, void *buf, size_t len, int flags,
             const struct sockaddr *to, socklen_t tolen,
             const struct sockaddr *from, socklen_t fromlen,
             union aux_addressing_info *auxaddr)
{
#if (!defined(IP_PKTINFO) && !defined(IPV6_PKTINFO)) || !defined(CMSG_SPACE)
    return sendto(s, buf, len, flags, to, tolen);
#else
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsgptr;
    char cbuf[CMSG_SPACE(sizeof(union pktinfo))];

    if (from == 0 || fromlen == 0 || from->sa_family != to->sa_family) {
    use_sendto:
        return sendto(s, buf, len, flags, to, tolen);
    }

    iov.iov_base = buf;
    iov.iov_len = len;
    /* Truncation?  */
    if (iov.iov_len != len)
        return EINVAL;
    memset(cbuf, 0, sizeof(cbuf));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *) to;
    msg.msg_namelen = tolen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    /* CMSG_FIRSTHDR needs a non-zero controllen, or it'll return NULL
       on Linux.  */
    msg.msg_controllen = sizeof(cbuf);
    cmsgptr = CMSG_FIRSTHDR(&msg);
    msg.msg_controllen = 0;

    switch (from->sa_family) {
#if defined(IP_PKTINFO)
    case AF_INET:
        if (fromlen != sizeof(struct sockaddr_in))
            goto use_sendto;
        cmsgptr->cmsg_level = IPPROTO_IP;
        cmsgptr->cmsg_type = IP_PKTINFO;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        {
            struct in_pktinfo *p = (struct in_pktinfo *)CMSG_DATA(cmsgptr);
            const struct sockaddr_in *from4 = (const struct sockaddr_in *)from;
            p->ipi_spec_dst = from4->sin_addr;
        }
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
        break;
#endif
#if defined(IPV6_PKTINFO) && defined(HAVE_STRUCT_IN6_PKTINFO)
    case AF_INET6:
        if (fromlen != sizeof(struct sockaddr_in6))
            goto use_sendto;
        cmsgptr->cmsg_level = IPPROTO_IPV6;
        cmsgptr->cmsg_type = IPV6_PKTINFO;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        {
            struct in6_pktinfo *p = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
            const struct sockaddr_in6 *from6 =
                (const struct sockaddr_in6 *)from;
            p->ipi6_addr = from6->sin6_addr;
            /*
             * Because of the possibility of asymmetric routing, we
             * normally don't want to specify an interface.  However,
             * Mac OS X doesn't like sending from a link-local address
             * (which can come up in testing at least, if you wind up
             * with a "foo.local" name) unless we do specify the
             * interface.
             */
            if (IN6_IS_ADDR_LINKLOCAL(&from6->sin6_addr))
                p->ipi6_ifindex = auxaddr->ipv6_ifindex;
            /* otherwise, already zero */
        }
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
        break;
#endif
    default:
        goto use_sendto;
    }
    return sendmsg(s, &msg, flags);
#endif
}

struct udp_dispatch_state {
    void *handle;
    const char *prog;
    int port_fd;
    krb5_address addr;
    krb5_fulladdr faddr;
    socklen_t saddr_len;
    socklen_t daddr_len;
    struct sockaddr_storage saddr;
    struct sockaddr_storage daddr;
    union aux_addressing_info auxaddr;
    krb5_data request;
    char pktbuf[MAX_DGRAM_SIZE];
};

static void
process_packet_response(void *arg, krb5_error_code code, krb5_data *response)
{
    struct udp_dispatch_state *state = arg;
    int cc;

    if (code)
        com_err(state->prog ? state->prog : NULL, code,
                _("while dispatching (udp)"));
    if (code || response == NULL)
        goto out;

    cc = send_to_from(state->port_fd, response->data,
                      (socklen_t) response->length, 0,
                      (struct sockaddr *)&state->saddr, state->saddr_len,
                      (struct sockaddr *)&state->daddr, state->daddr_len,
                      &state->auxaddr);
    if (cc == -1) {
        /* Note that the local address (daddr*) has no port number
         * info associated with it. */
        char saddrbuf[NI_MAXHOST], sportbuf[NI_MAXSERV];
        char daddrbuf[NI_MAXHOST];
        int e = errno;

        if (getnameinfo((struct sockaddr *)&state->daddr, state->daddr_len,
                        daddrbuf, sizeof(daddrbuf), 0, 0,
                        NI_NUMERICHOST) != 0) {
            strlcpy(daddrbuf, "?", sizeof(daddrbuf));
        }

        if (getnameinfo((struct sockaddr *)&state->saddr, state->saddr_len,
                        saddrbuf, sizeof(saddrbuf), sportbuf, sizeof(sportbuf),
                        NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
            strlcpy(saddrbuf, "?", sizeof(saddrbuf));
            strlcpy(sportbuf, "?", sizeof(sportbuf));
        }

        com_err(state->prog, e, _("while sending reply to %s/%s from %s"),
                saddrbuf, sportbuf, daddrbuf);
        goto out;
    }
    if ((size_t)cc != response->length) {
        com_err(state->prog, 0, _("short reply write %d vs %d\n"),
                response->length, cc);
    }

out:
    krb5_free_data(get_context(state->handle), response);
    free(state);
}

static void
process_packet(verto_ctx *ctx, verto_ev *ev)
{
    int cc;
    struct connection *conn;
    struct udp_dispatch_state *state;

    conn = verto_get_private(ev);

    state = malloc(sizeof(*state));
    if (!state) {
        com_err(conn->prog, ENOMEM, _("while dispatching (udp)"));
        return;
    }

    state->handle = conn->handle;
    state->prog = conn->prog;
    state->port_fd = verto_get_fd(ev);
    assert(state->port_fd >= 0);

    state->saddr_len = sizeof(state->saddr);
    state->daddr_len = sizeof(state->daddr);
    memset(&state->auxaddr, 0, sizeof(state->auxaddr));
    cc = recv_from_to(state->port_fd, state->pktbuf, sizeof(state->pktbuf), 0,
                      (struct sockaddr *)&state->saddr, &state->saddr_len,
                      (struct sockaddr *)&state->daddr, &state->daddr_len,
                      &state->auxaddr);
    if (cc == -1) {
        if (errno != EINTR && errno != EAGAIN
            /*
             * This is how Linux indicates that a previous transmission was
             * refused, e.g., if the client timed out before getting the
             * response packet.
             */
            && errno != ECONNREFUSED
        )
            com_err(conn->prog, errno, _("while receiving from network"));
        free(state);
        return;
    }
    if (!cc) { /* zero-length packet? */
        free(state);
        return;
    }

#if 0
    if (state->daddr_len > 0) {
        char addrbuf[100];
        if (getnameinfo(ss2sa(&state->daddr), state->daddr_len,
                        addrbuf, sizeof(addrbuf),
                        0, 0, NI_NUMERICHOST))
            strlcpy(addrbuf, "?", sizeof(addrbuf));
        com_err(conn->prog, 0, _("pktinfo says local addr is %s"), addrbuf);
    }
#endif

    if (state->daddr_len == 0 && conn->type == CONN_UDP) {
        /*
         * If the PKTINFO option isn't set, this socket should be bound to a
         * specific local address.  This info probably should've been saved in
         * our socket data structure at setup time.
         */
        state->daddr_len = sizeof(state->daddr);
        if (getsockname(state->port_fd, (struct sockaddr *)&state->daddr,
                        &state->daddr_len) != 0)
            state->daddr_len = 0;
        /* On failure, keep going anyways. */
    }

    state->request.length = cc;
    state->request.data = state->pktbuf;
    state->faddr.address = &state->addr;
    init_addr(&state->faddr, ss2sa(&state->saddr));
    /* This address is in net order. */
    dispatch(state->handle, ss2sa(&state->daddr), &state->faddr,
             &state->request, 0, ctx, process_packet_response, state);
}

static int
kill_lru_tcp_or_rpc_connection(void *handle, verto_ev *newev)
{
    struct connection *c = NULL, *oldest_c = NULL;
    verto_ev *ev, *oldest_ev = NULL;
    int i, fd = -1;

    krb5_klog_syslog(LOG_INFO, _("too many connections"));

    FOREACH_ELT (events, i, ev) {
        if (ev == newev)
            continue;

        c = verto_get_private(ev);
        if (!c)
            continue;
        if (c->type != CONN_TCP && c->type != CONN_RPC)
            continue;
#if 0
        krb5_klog_syslog(LOG_INFO, "fd %d started at %ld",
                         verto_get_fd(oldest_ev),
                         c->start_time);
#endif
        if (oldest_c == NULL
            || oldest_c->start_time > c->start_time) {
            oldest_ev = ev;
            oldest_c = c;
        }
    }
    if (oldest_c != NULL) {
        krb5_klog_syslog(LOG_INFO, _("dropping %s fd %d from %s"),
                         c->type == CONN_RPC ? "rpc" : "tcp",
                         verto_get_fd(oldest_ev), oldest_c->addrbuf);
        if (oldest_c->type == CONN_RPC)
            oldest_c->rpc_force_close = 1;
        verto_del(oldest_ev);
    }
    return fd;
}

static void
accept_tcp_connection(verto_ctx *ctx, verto_ev *ev)
{
    int s;
    struct sockaddr_storage addr_s;
    struct sockaddr *addr = (struct sockaddr *)&addr_s;
    socklen_t addrlen = sizeof(addr_s);
    struct socksetup sockdata;
    struct connection *newconn, *conn;
    char tmpbuf[10];
    verto_ev *newev;

    conn = verto_get_private(ev);
    s = accept(verto_get_fd(ev), addr, &addrlen);
    if (s < 0)
        return;
    set_cloexec_fd(s);
#ifndef _WIN32
    if (s >= FD_SETSIZE) {
        close(s);
        return;
    }
#endif
    setnbio(s), setnolinger(s), setkeepalive(s);

    sockdata.ctx = ctx;
    sockdata.handle = conn->handle;
    sockdata.prog = conn->prog;
    sockdata.retval = 0;

    newev = add_tcp_read_fd(&sockdata, s);
    if (newev == NULL) {
        close(s);
        return;
    }
    newconn = verto_get_private(newev);

    if (getnameinfo((struct sockaddr *)&addr_s, addrlen,
                    newconn->addrbuf, sizeof(newconn->addrbuf),
                    tmpbuf, sizeof(tmpbuf),
                    NI_NUMERICHOST | NI_NUMERICSERV))
        strlcpy(newconn->addrbuf, "???", sizeof(newconn->addrbuf));
    else {
        char *p, *end;
        p = newconn->addrbuf;
        end = p + sizeof(newconn->addrbuf);
        p += strlen(p);
        if ((size_t)(end - p) > 2 + strlen(tmpbuf)) {
            *p++ = '.';
            strlcpy(p, tmpbuf, end - p);
        }
    }
#if 0
    krb5_klog_syslog(LOG_INFO, "accepted TCP connection on socket %d from %s",
                     s, newconn->addrbuf);
#endif

    newconn->addr_s = addr_s;
    newconn->addrlen = addrlen;
    newconn->bufsiz = 1024 * 1024;
    newconn->buffer = malloc(newconn->bufsiz);
    newconn->start_time = time(0);

    if (++tcp_or_rpc_data_counter > max_tcp_or_rpc_data_connections)
        kill_lru_tcp_or_rpc_connection(conn->handle, newev);

    if (newconn->buffer == 0) {
        com_err(conn->prog, errno,
                _("allocating buffer for new TCP session from %s"),
                newconn->addrbuf);
        verto_del(newev);
        return;
    }
    newconn->offset = 0;
    newconn->faddr.address = &newconn->kaddr;
    init_addr(&newconn->faddr, ss2sa(&newconn->addr_s));
    SG_SET(&newconn->sgbuf[0], newconn->lenbuf, 4);
    SG_SET(&newconn->sgbuf[1], 0, 0);
}

struct tcp_dispatch_state {
    struct sockaddr_storage local_saddr;
    struct connection *conn;
    krb5_data request;
    verto_ctx *ctx;
    int sock;
};

static void
process_tcp_response(void *arg, krb5_error_code code, krb5_data *response)
{
    struct tcp_dispatch_state *state = arg;
    verto_ev *ev;

    assert(state);
    state->conn->response = response;

    if (code)
        com_err(state->conn->prog, code, _("while dispatching (tcp)"));
    if (code || !response)
        goto kill_tcp_connection;

    /* Queue outgoing response. */
    store_32_be(response->length, state->conn->lenbuf);
    SG_SET(&state->conn->sgbuf[1], response->data, response->length);
    state->conn->sgp = state->conn->sgbuf;
    state->conn->sgnum = 2;

    ev = make_event(state->ctx, VERTO_EV_FLAG_IO_WRITE | VERTO_EV_FLAG_PERSIST,
                    process_tcp_connection_write, state->sock, state->conn, 1);
    if (ev) {
        free(state);
        return;
    }

kill_tcp_connection:
    tcp_or_rpc_data_counter--;
    free_connection(state->conn);
    close(state->sock);
    free(state);
}

/* Creates the tcp_dispatch_state and deletes the verto event. */
static struct tcp_dispatch_state *
prepare_for_dispatch(verto_ctx *ctx, verto_ev *ev)
{
    struct tcp_dispatch_state *state;

    state = malloc(sizeof(*state));
    if (!state) {
        krb5_klog_syslog(LOG_ERR, _("error allocating tcp dispatch private!"));
        return NULL;
    }
    state->conn = verto_get_private(ev);
    state->sock = verto_get_fd(ev);
    state->ctx = ctx;
    verto_set_private(ev, NULL, NULL); /* Don't close the fd or free conn! */
    remove_event_from_set(ev); /* Remove it from the set. */
    verto_del(ev);
    return state;
}

static void
process_tcp_connection_read(verto_ctx *ctx, verto_ev *ev)
{
    struct tcp_dispatch_state *state = NULL;
    struct connection *conn = NULL;
    ssize_t nread;
    size_t len;

    conn = verto_get_private(ev);

    /*
     * Read message length and data into one big buffer, already allocated
     * at connect time.  If we have a complete message, we stop reading, so
     * we should only be here if there is no data in the buffer, or only an
     * incomplete message.
     */
    if (conn->offset < 4) {
        krb5_data *response = NULL;

        /* msglen has not been computed.  XXX Doing at least two reads
         * here, letting the kernel worry about buffering. */
        len = 4 - conn->offset;
        nread = SOCKET_READ(verto_get_fd(ev),
                            conn->buffer + conn->offset, len);
        if (nread < 0) /* error */
            goto kill_tcp_connection;
        if (nread == 0) /* eof */
            goto kill_tcp_connection;
        conn->offset += nread;
        if (conn->offset == 4) {
            unsigned char *p = (unsigned char *)conn->buffer;
            conn->msglen = load_32_be(p);
            if (conn->msglen > conn->bufsiz - 4) {
                krb5_error_code err;
                /* Message too big. */
                krb5_klog_syslog(LOG_ERR, _("TCP client %s wants %lu bytes, "
                                            "cap is %lu"), conn->addrbuf,
                                 (unsigned long) conn->msglen,
                                 (unsigned long) conn->bufsiz - 4);
                /* XXX Should return an error.  */
                err = make_toolong_error (conn->handle,
                                          &response);
                if (err) {
                    krb5_klog_syslog(LOG_ERR, _("error constructing "
                                                "KRB_ERR_FIELD_TOOLONG error! %s"),
                                     error_message(err));
                    goto kill_tcp_connection;
                }

                state = prepare_for_dispatch(ctx, ev);
                if (!state) {
                    krb5_free_data(get_context(conn->handle), response);
                    goto kill_tcp_connection;
                }
                process_tcp_response(state, 0, response);
            }
        }
    } else {
        /* msglen known. */
        socklen_t local_saddrlen = sizeof(struct sockaddr_storage);
        struct sockaddr *local_saddrp = NULL;

        len = conn->msglen - (conn->offset - 4);
        nread = SOCKET_READ(verto_get_fd(ev),
                            conn->buffer + conn->offset, len);
        if (nread < 0) /* error */
            goto kill_tcp_connection;
        if (nread == 0) /* eof */
            goto kill_tcp_connection;
        conn->offset += nread;
        if (conn->offset < conn->msglen + 4)
            return;

        /* Have a complete message, and exactly one message. */
        state = prepare_for_dispatch(ctx, ev);
        if (!state)
            goto kill_tcp_connection;

        state->request.length = conn->msglen;
        state->request.data = conn->buffer + 4;

        if (getsockname(verto_get_fd(ev), ss2sa(&state->local_saddr),
                        &local_saddrlen) == 0)
            local_saddrp = ss2sa(&state->local_saddr);

        dispatch(state->conn->handle, local_saddrp, &conn->faddr,
                 &state->request, 1, ctx, process_tcp_response, state);
    }

    return;

kill_tcp_connection:
    verto_del(ev);
}

static void
process_tcp_connection_write(verto_ctx *ctx, verto_ev *ev)
{
    struct connection *conn;
    SOCKET_WRITEV_TEMP tmp;
    ssize_t nwrote;
    int sock;

    conn = verto_get_private(ev);
    sock = verto_get_fd(ev);

    nwrote = SOCKET_WRITEV(sock, conn->sgp,
                           conn->sgnum, tmp);
    if (nwrote > 0) { /* non-error and non-eof */
        while (nwrote) {
            sg_buf *sgp = conn->sgp;
            if ((size_t)nwrote < SG_LEN(sgp)) {
                SG_ADVANCE(sgp, (size_t)nwrote);
                nwrote = 0;
            } else {
                nwrote -= SG_LEN(sgp);
                conn->sgp++;
                conn->sgnum--;
                if (conn->sgnum == 0 && nwrote != 0)
                    abort();
            }
        }

        /* If we still have more data to send, just return so that
         * the main loop can call this function again when the socket
         * is ready for more writing. */
        if (conn->sgnum > 0)
            return;
    }

    /* Finished sending.  We should go back to reading, though if we
     * sent a FIELD_TOOLONG error in reply to a length with the high
     * bit set, RFC 4120 says we have to close the TCP stream. */
    verto_del(ev);
}

void
loop_free(verto_ctx *ctx)
{
    verto_free(ctx);
    FREE_SET_DATA(events);
    FREE_SET_DATA(udp_port_data);
    FREE_SET_DATA(tcp_port_data);
    FREE_SET_DATA(rpc_svc_data);
}

static int
have_event_for_fd(int fd)
{
    verto_ev *ev;
    int i;

    FOREACH_ELT(events, i, ev) {
        if (verto_get_fd(ev) == fd)
            return 1;
    }

    return 0;
}

static void
accept_rpc_connection(verto_ctx *ctx, verto_ev *ev)
{
    struct socksetup sockdata;
    struct connection *conn;
    fd_set fds;
    register int s;

    conn = verto_get_private(ev);

    sockdata.ctx = ctx;
    sockdata.handle = conn->handle;
    sockdata.prog = conn->prog;
    sockdata.retval = 0;

    /* Service the woken RPC listener descriptor. */
    FD_ZERO(&fds);
    FD_SET(verto_get_fd(ev), &fds);
    svc_getreqset(&fds);

    /* Scan svc_fdset for any new connections. */
    for (s = 0; s < FD_SETSIZE; s++) {
        struct sockaddr_storage addr_s;
        struct sockaddr *addr = (struct sockaddr *) &addr_s;
        socklen_t addrlen = sizeof(addr_s);
        struct connection *newconn;
        char tmpbuf[10];
        verto_ev *newev;

        /* If we already have this fd, continue. */
        if (!FD_ISSET(s, &svc_fdset) || have_event_for_fd(s))
            continue;

        newev = add_rpc_data_fd(&sockdata, s);
        if (newev == NULL)
            continue;
        newconn = verto_get_private(newev);

        set_cloexec_fd(s);
#if 0
        setnbio(s), setnolinger(s), setkeepalive(s);
#endif

        if (getpeername(s, addr, &addrlen) ||
            getnameinfo(addr, addrlen,
                        newconn->addrbuf,
                        sizeof(newconn->addrbuf),
                        tmpbuf, sizeof(tmpbuf),
                        NI_NUMERICHOST | NI_NUMERICSERV)) {
            strlcpy(newconn->addrbuf, "???",
                    sizeof(newconn->addrbuf));
        } else {
            char *p, *end;
            p = newconn->addrbuf;
            end = p + sizeof(newconn->addrbuf);
            p += strlen(p);
            if ((size_t)(end - p) > 2 + strlen(tmpbuf)) {
                *p++ = '.';
                strlcpy(p, tmpbuf, end - p);
            }
        }
#if 0
        krb5_klog_syslog(LOG_INFO, _("accepted RPC connection on socket %d "
                                     "from %s"), s, newconn->addrbuf);
#endif

        newconn->addr_s = addr_s;
        newconn->addrlen = addrlen;
        newconn->start_time = time(0);

        if (++tcp_or_rpc_data_counter > max_tcp_or_rpc_data_connections)
            kill_lru_tcp_or_rpc_connection(newconn->handle, newev);

        newconn->faddr.address = &newconn->kaddr;
        init_addr(&newconn->faddr, ss2sa(&newconn->addr_s));
    }
}

static void
process_rpc_connection(verto_ctx *ctx, verto_ev *ev)
{
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(verto_get_fd(ev), &fds);
    svc_getreqset(&fds);

    if (!FD_ISSET(verto_get_fd(ev), &svc_fdset))
        verto_del(ev);
}

#endif /* INET */
