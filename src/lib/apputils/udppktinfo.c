/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2016 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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

#include "udppktinfo.h"

#include <netinet/in.h>
#include <sys/socket.h>

/* Use RFC 3542 API below, but fall back from IPV6_RECVPKTINFO to IPV6_PKTINFO
 * for RFC 2292 implementations. */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

/* Parallel, though not standardized. */
#if !defined(IP_RECVPKTINFO) && defined(IP_PKTINFO)
#define IP_RECVPKTINFO IP_PKTINFO
#endif /* IP_RECVPKTINFO */

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
#endif

/*
 * Set pktinfo option on a socket. Takes a socket and the socket address family
 * as arguments.
 *
 * Returns 0 on success, EINVAL if pktinfo is not supported for the address
 * family.
 */
krb5_error_code
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

/*
 * Receive a message from a socket.
 *
 * Arguments:
 *  socket
 *  buf     - The buffer to store the message in.
 *  len     - buf length
 *  flags
 *  from    - Set to the address that sent the message
 *  fromlen
 *  to      - Set to the address that the message was sent to if possible.
 *            May not be set in certain cases such as if pktinfo support is
 *            missing. May be NULL.
 *  tolen
 *  auxaddr - Miscellaneous address information.
 *
 * Returns 0 on success, otherwise an error code.
 */
krb5_error_code
recv_from_to(int socket, void *buf, size_t len, int flags,
             struct sockaddr *from, socklen_t *fromlen,
             struct sockaddr *to, socklen_t *tolen,
             aux_addressing_info *auxaddr)

{
#if (!defined(IP_PKTINFO) && !defined(IPV6_PKTINFO)) || !defined(CMSG_SPACE)
    if (to && tolen) {
        /* Clobber with something recognizeable in case we try to use
         *          the address.  */
        memset(to, 0x40, *tolen);
        *tolen = 0;
    }

    return recvfrom(socket, buf, len, flags, from, fromlen);
#else
    int r;
    struct iovec iov;
    char cmsg[CMSG_SPACE(sizeof(union pktinfo))];
    struct cmsghdr *cmsgptr;
    struct msghdr msg;

    if (!to || !tolen)
        return recvfrom(socket, buf, len, flags, from, fromlen);

    /* Clobber with something recognizeable in case we can't extract
     *      the address but try to use it anyways.  */
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

    r = recvmsg(socket, &msg, flags);
    if (r < 0)
        return r;
    *fromlen = msg.msg_namelen;

    /* On Darwin (and presumably all *BSD with KAME stacks),
     *      CMSG_FIRSTHDR doesn't check for a non-zero controllen.  RFC
     *      3542 recommends making this check, even though the (new) spec
     *      for CMSG_FIRSTHDR says it's supposed to do the check.  */
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

/*
 * Send a message to an address.
 *
 * Arguments:
 *  socket
 *  buf     - The message to send.
 *  len     - buf length
 *  flags
 *  to      - The address to send the message to.
 *  tolen
 *  from    - The address to attempt to send the message from. May be NULL.
 *  fromlen
 *  auxaddr - Miscellaneous address information.
 *
 * Returns 0 on success, otherwise an error code.
 */
krb5_error_code
send_to_from(int socket, void *buf, size_t len, int flags,
             const struct sockaddr *to, socklen_t tolen,
             const struct sockaddr *from, socklen_t fromlen,
             aux_addressing_info *auxaddr)
{
#if (!defined(IP_PKTINFO) && !defined(IPV6_PKTINFO)) || !defined(CMSG_SPACE)
    return sendto(socket, buf, len, flags, to, tolen);
#else
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsgptr;
    char cbuf[CMSG_SPACE(sizeof(union pktinfo))];

    if (from == 0 || fromlen == 0 || from->sa_family != to->sa_family) {
use_sendto:
        return sendto(socket, buf, len, flags, to, tolen);
    }

    iov.iov_base = buf;
    iov.iov_len = len;
    /* Truncation?  */
    if (iov.iov_len != len)
        return EINVAL;
    memset(cbuf, 0, sizeof(cbuf));
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)to;
    msg.msg_namelen = tolen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    /* CMSG_FIRSTHDR needs a non-zero controllen, or it'll return NULL
     *      on Linux.  */
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
    return sendmsg(socket, &msg, flags);
#endif
}
