/*
 * lib/krb5/os/sendto_kdc.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * 
 *
 * Send packet to KDC for realm; wait for response, retransmitting
 * as necessary.
 */

#define NEED_SOCKETS
#define NEED_LOWLEVEL_IO
#include "fake-addrinfo.h"
#include "k5-int.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#include "os-proto.h"

#ifdef _AIX
#include <sys/select.h>
#endif

/* For FIONBIO.  */
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#ifdef _WIN32
#define ENABLE_TCP 0 /* for now */
#else
#define ENABLE_TCP 1
#endif

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
krb5_sendto_kdc (context, message, realm, reply, use_master, tcp_only)
    krb5_context context;
    const krb5_data * message;
    const krb5_data * realm;
    krb5_data * reply;
    int use_master;
    int tcp_only;
{
    krb5_error_code retval;
    struct addrlist addrs;

    /*
     * find KDC location(s) for realm
     */

    /*
     * DO NOT depend on this staying as two separate loops.  We may change
     * the order, or we may integrate them into one loop.
     *
     * BUG: This code won't return "interesting" errors (e.g., out of mem,
     * bad config file) from locate_kdc.  KRB5_REALM_CANT_RESOLVE can be
     * ignored from one query of two, but if only one query is done, or
     * both return that error, it should be returned to the caller.  Also,
     * "interesting" errors (not KRB5_KDC_UNREACH) from sendto_{udp,tcp}
     * should probably be returned as well.
     */

    retval = (use_master ? KRB5_KDC_UNREACH : KRB5_REALM_UNKNOWN);

    if (!tcp_only
	&& ! krb5_locate_kdc(context, realm, &addrs, use_master, SOCK_DGRAM)) {
	if (addrs.naddrs > 0) {
	    retval = krb5int_sendto_udp (context, message, &addrs, reply);
	    krb5int_free_addrlist (&addrs);
	    if (retval == 0)
		return 0;
	}
    }

#if ENABLE_TCP
    if (! krb5_locate_kdc(context, realm, &addrs, use_master, SOCK_STREAM)) {
	if (addrs.naddrs > 0) {
	    retval = krb5int_sendto_tcp (context, message, &addrs, reply);
	    krb5int_free_addrlist (&addrs);
	    if (retval == 0)
		return 0;
	}
    }
#endif

    return retval;
}

static void debug_log_connect (int fd, struct addrinfo *ai)
{
#ifdef DEBUG
    char addrbuf[NI_MAXHOST], portbuf[NI_MAXSERV];
    if (0 != getnameinfo (ai->ai_addr, ai->ai_addrlen,
			  addrbuf, sizeof (addrbuf), portbuf, sizeof (portbuf),
			  NI_NUMERICHOST | NI_NUMERICSERV))
	strcpy (addrbuf, "??"), strcpy (portbuf, "??");
    fprintf (stderr, " fd %d; connecting to %s port %s...\n", fd,
	     addrbuf, portbuf);
#endif
}

#ifdef DEBUG
#define dperror(MSG) perror(MSG)
#define dfprintf(ARGLIST) fprintf ARGLIST
#else
#define dperror(MSG) ((void)(MSG))
#define dfprintf(ARGLIST) ((void)0)
#endif

krb5_error_code
krb5int_sendto_udp (krb5_context context, const krb5_data *message,
		    const struct addrlist *addrs, krb5_data *reply)
{
    int timeout, host, i;
    int sent, nready;
    krb5_error_code retval;
    SOCKET *socklist;
    fd_set readable;
    struct timeval waitlen;
    int cc;

    socklist = (SOCKET *)malloc(addrs->naddrs * sizeof(SOCKET));
    if (socklist == NULL) {
	return ENOMEM;
    }
    for (i = 0; i < addrs->naddrs; i++)
	socklist[i] = INVALID_SOCKET;

    if (!(reply->data = malloc(krb5_max_dgram_size))) {
	krb5_xfree(socklist);
	return ENOMEM;
    }
    reply->length = krb5_max_dgram_size;

#if 0
    /*
     * Not needed for Windows, since it's done by the DLL
     * initialization. XXX What about for the Macintosh?
     *
     * See below for commented out SOCKET_CLEANUP()
     */
    if (SOCKET_INITIALIZE()) {  /* PC needs this for some tcp/ip stacks */
	krb5_xfree(socklist);
	free(reply->data);
        return SOCKET_ERRNO;
    }
#endif

    /*
     * do exponential backoff.
     */

    for (timeout = krb5_skdc_timeout_1; timeout < krb5_max_skdc_timeout;
	 timeout <<= krb5_skdc_timeout_shift) {
	sent = 0;
	for (host = 0; host < addrs->naddrs; host++) {
	    struct addrinfo *ai = addrs->addrs[host];
	    if (ai->ai_socktype != SOCK_DGRAM)
		continue;
	    /* Send to the host, wait timeout seconds for a response,
	       then move on. */
	    /* Cache some sockets for each host.  */
	    if (socklist[host] == INVALID_SOCKET) {
		/* XXX 4.2/4.3BSD has PF_xxx = AF_xxx, so the socket
		   creation here will work properly... */
		/*
		 * From socket(2):
		 *
		 * The protocol specifies a particular protocol to be
		 * used with the socket.  Normally only a single
		 * protocol exists to support a particular socket type
		 * within a given protocol family.
		 */
		dfprintf((stderr, "getting dgram socket in family %d...",
			  ai->ai_family));
		socklist[host] = socket(ai->ai_family, SOCK_DGRAM, 0);
		if (socklist[host] == INVALID_SOCKET) {
		    dfprintf((stderr, "socket: %s\naf was %d\n",
			      strerror(errno), ai->ai_family));
		    continue;		/* try other hosts */
		}
		debug_log_connect(socklist[host], ai);
		/* have a socket to send/recv from */
		/* On BSD systems, a connected UDP socket will get connection
		   refused and net unreachable errors while an unconnected
		   socket will time out, so use connect, send, recv instead of
		   sendto, recvfrom.  The connect here may return an error if
		   the destination host is known to be unreachable. */
		if (connect(socklist[host], ai->ai_addr,
			    ai->ai_addrlen) == SOCKET_ERROR) {
		    dperror ("connect");
		    continue;
		}
	    }
	    dfprintf((stderr, "sending..."));
	    if (send(socklist[host],
		       message->data, message->length, 0) 
		!= message->length) {
		dperror ("sendto");
		continue;
	    }
	    dfprintf((stderr, "\n"));
	retry:
	    waitlen.tv_usec = 0;
	    waitlen.tv_sec = timeout;
	    FD_ZERO(&readable);
	    FD_SET(socklist[host], &readable);
	    if ((nready = select(SOCKET_NFDS(socklist[host]),
				 &readable,
				 0,
				 0,
				 &waitlen))) {
		if (nready == SOCKET_ERROR) {
		    if (SOCKET_ERRNO == SOCKET_EINTR)
			goto retry;
		    retval = SOCKET_ERRNO;
		    goto out;
		}
		if ((cc = recv(socklist[host],
			       reply->data, reply->length, 
			       0)) == SOCKET_ERROR)
		  {
		    /* man page says error could be:
		       EBADF: won't happen
		       ENOTSOCK: it's a socket.
		       EWOULDBLOCK: not marked non-blocking, and we selected.
		       EINTR: could happen
		       EFAULT: we allocated the reply packet.

		       In addition, net related errors like ECONNREFUSED
		       are possble (but undocumented).  Assume anything
		       other than EINTR is a permanent error for the
		       server (i.e. don't set sent = 1).
		       */

		    if (SOCKET_ERRNO == SOCKET_EINTR)
		      sent = 1;
		    continue;
		  }

		/* We might consider here verifying that the reply
		   came from one of the KDC's listed for that address type,
		   but that check can be fouled by some implementations of
		   some network types which might show a loopback return
		   address, for example, if the KDC is on the same host
		   as the client. */

		reply->length = cc;
		retval = 0;
		dfprintf((stderr, "got answer on fd %d\n", socklist[host]));
		goto out;
	    } else if (nready == 0) {
		/* timeout */
	        sent = 1;
	    }
	    /* not ready, go on to next server */
	}
	if (!sent) {
	    /* never were able to send to any servers; give up */
	    retval = KRB5_KDC_UNREACH;
	    dfprintf((stderr, "no KDCs to contact\n"));
	    goto out;
	}
    }
    retval = KRB5_KDC_UNREACH;
    dfprintf((stderr, "no answer\n"));
 out:
    for (i = 0; i < addrs->naddrs; i++)
	if (socklist[i] != INVALID_SOCKET)
	    (void) closesocket (socklist[i]);
#if 0
    SOCKET_CLEANUP();                           /* Done with sockets for now */
#endif
    krb5_xfree(socklist);
    if (retval) {
	free(reply->data);
	reply->data = 0;
	reply->length = 0;
    }
    return retval;
}

#if ENABLE_TCP
/*
 * To do:
 * - TCP NOPUSH/CORK socket options?
 * - error codes that don't suck
 * - getsockopt(SO_ERROR) to check connect status
 */

#ifdef DEBUG
static const char *state_strings[] = {
    "CONNECTING", "WRITING", "READING", "FAILED"
};
#endif
struct conn_state {
    SOCKET fd;
    krb5_error_code err;
    enum { CONNECTING, WRITING, READING, FAILED } state;
    char *buf;
    size_t bufsize;
    unsigned char bufsizebytes[4];
    size_t bufsizebytes_read;
    struct iovec iov[2];
    struct iovec *iovp;
    int iov_count;
};

struct select_state {
    int max, nfds;
    fd_set rfds, wfds;
    struct timeval end_time;
};

#ifdef DEBUG
static void
print_fdsets (FILE *f, fd_set *rfds, fd_set *wfds, int maxfd)
{
    int i;
    for (i = 0; i < maxfd; i++) {
	int r = FD_ISSET(i, rfds);
	int w = FD_ISSET(i, wfds);
	if (r || w) {
	    fprintf(f, " %d", i);
	    if (r)
		fprintf(f, "r");
	    if (w)
		fprintf(f, "w");
	}
    }
}
#endif

/*
 * Call select and return results.
 * Input: interesting file descriptors and absolute timeout
 * Output: select return value (-1 or num fds ready) and fd_sets
 * Return: 0 (for i/o available or timeout) or error code.
 */
static krb5_error_code
call_select (struct select_state *in, struct select_state *out, int *sret)
{
    struct timeval now;
    krb5_error_code e;

    *out = *in;
    if (gettimeofday(&now, 0)) {
	e = errno;
	dperror("gettimeofday");
	return e;
    }
    out->end_time.tv_sec -= now.tv_sec;
    out->end_time.tv_usec -= now.tv_usec;
    if (out->end_time.tv_usec < 0) {
	out->end_time.tv_usec += 1000000;
	out->end_time.tv_sec--;
    }
    if (out->end_time.tv_sec < 0) {
	*sret = 0;
	return 0;
    }
#ifdef DEBUG
    fprintf(stderr, "selecting on %d sockets [", out->nfds);
    print_fdsets(stderr, &out->rfds, &out->wfds, out->max);
    fprintf(stderr, " ] timeout %ld.%06ld\n", (long) out->end_time.tv_sec,
	    (long) out->end_time.tv_usec);
#endif
    *sret = select(out->max, &out->rfds, &out->wfds, 0, &out->end_time);
    e = errno;
#ifdef DEBUG
    fprintf(stderr, "select returns %d", *sret);
    if (*sret < 0)
	fprintf(stderr, ", errno = %d/%s\n", e, strerror(e));
    else if (*sret == 0)
	fprintf(stderr, " (timeout)\n");
    else {
	fprintf(stderr, ":");
	print_fdsets(stderr, &out->rfds, &out->wfds, out->max);
	fprintf(stderr, "\n");
    }
#endif
    if (*sret < 0)
	return errno;
    return 0;
}

static int
make_nonblocking (int fd)
{
    static const int one = 1;

    if (ioctlsocket (fd, FIONBIO, &one)) {
	dperror("sendto_kdc_tcp: ioctl(FIONBIO)");
	return errno;
    }
    return 0;
}

static int
start_tcp_connection (struct conn_state *state, struct addrinfo *ai)
{
    int fd, e;

    state->err = 0;
    state->buf = 0;
    state->bufsizebytes_read = 0;
    state->iovp = state->iov;
    state->iov[0].iov_base = (char *) state->bufsizebytes;
    state->iov[0].iov_len = 4;
    state->iov[1].iov_base = 0;
    state->iov[1].iov_len = 0;
    state->iov_count = 2;

    dfprintf((stderr, "getting stream socket in family %d...", ai->ai_family));
    fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) {
	state->err = errno;
	dfprintf((stderr, "socket: %s connecting with af %d\n",
		  strerror (state->err), ai->ai_family));
	return -1;		/* try other hosts */
    }
    debug_log_connect(fd, ai);
    /* Make it non-blocking.  */
    make_nonblocking(fd);

    /* Start connecting to KDC.  */
    e = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (e != 0) {
	/*
	 * This is the path that should be followed for non-blocking
	 * connections.
	 */
	if (SOCKET_ERRNO == EINPROGRESS || SOCKET_ERRNO == EWOULDBLOCK) {
	    state->state = CONNECTING;
	} else {
	    state->err = SOCKET_ERRNO;
	    dfprintf((stderr, "socket error %d in connect()\n", state->err));
	    state->state = FAILED;
	    return -2;
	}
    } else {
	/*
	 * Connect returned zero even though we tried to make it
	 * non-blocking, which should have caused it to return before
	 * finishing the connection.  Oh well.  Someone's network
	 * stack is broken, but if they gave us a connection, use it.
	 */
	state->state = WRITING;
    }

    state->fd = fd;
    return 0;
}

static void
iov_advance (struct iovec *iov, int how_far)
{
    if (iov->iov_len < how_far)
	abort();
    /* Can't do math on void pointers.  */
    iov->iov_base = (char *) iov->iov_base + how_far;
    iov->iov_len -= how_far;
}

/* Return nonzero only if we're finished and the caller should exit
   its loop.  This happens in two cases: We have a complete message,
   or the socket has closed and no others are open.  */
static int
service_tcp_fd (struct conn_state *conn, struct select_state *selstate,
		int can_read, int can_write)
{
    krb5_error_code e = 0;
    int nwritten, nread;

#ifdef DEBUG
    /* index with can_read + 2 * can_write */
    static const char *const select_states[] = {
	"cannot_read_or_write??",
	"can_read", "can_write", "can_read/can_write",
    };
    fprintf(stderr, "handling %s on fd %d in state %s\n",
	    select_states[can_read + 2 * can_write],
	    conn->fd, state_strings[(int) conn->state]);
#endif

    if (!can_read && !can_write)
	abort();
    switch (conn->state) {

    case CONNECTING:
	if (can_read) {
	    /* Bad -- the KDC shouldn't be sending to us first.  */
	    e = EINVAL /* ?? */;
	kill_conn:
	    conn->state = FAILED;
	    shutdown(conn->fd, 2);
	    FD_CLR(conn->fd, &selstate->rfds);
	    FD_CLR(conn->fd, &selstate->wfds);
	    conn->err = e;
	    dfprintf((stderr, "abandoning connection %d: %s\n",
		     conn->fd, strerror(e)));
	    /* Fix up max fd for next select call.  */
	    if (selstate->max == 1 + conn->fd) {
		while (selstate->max > 0
		       && ! FD_ISSET(selstate->max-1, &selstate->rfds)
		       && ! FD_ISSET(selstate->max-1, &selstate->wfds))
		    selstate->max--;
		dfprintf((stderr, "new max_fd + 1 is %d\n", selstate->max));
	    }
	    selstate->nfds--;
	    if (e == EINVAL) {
		closesocket(conn->fd);
		conn->fd = INVALID_SOCKET;
	    }
	    return e == 0;
	}

	/*
	 * Connect finished -- but did it succeed or fail?
	 * Try writing, I guess, and find out.
	 */
	conn->state = WRITING;
	goto try_writing;

    case WRITING:
	if (can_read) {
	    e = E2BIG;
	    /* Bad -- the KDC shouldn't be sending anything yet.  */
	    goto kill_conn;
	}

	try_writing:
	dfprintf((stderr, "trying to writev %d (%d bytes) to fd %d\n",
		  conn->iov_count,
		  ((conn->iov_count == 2 ? conn->iovp[1].iov_len : 0)
		   + conn->iovp[0].iov_len),
		  conn->fd));
	nwritten = writev(conn->fd, conn->iovp,
			  conn->iov_count);
	if (nwritten < 0) {
	    e = SOCKET_ERRNO;
	    dfprintf((stderr, "failed: %s\n", strerror(e)));
	    goto kill_conn;
	}
	dfprintf((stderr, "wrote %d bytes\n", nwritten));
	while (nwritten) {
	    struct iovec *iovp = conn->iovp;
	    if (nwritten < iovp->iov_len) {
		iov_advance(iovp, nwritten);
		nwritten = 0;
	    } else {
		nwritten -= conn->iovp->iov_len;
		conn->iovp++;
		conn->iov_count--;
		if (conn->iov_count == 0 && nwritten != 0)
		    /* Wrote more than we wanted to?  */
		    abort();
	    }
	}
	if (conn->iov_count == 0) {
	    /* Done writing, switch to reading.  */
	    shutdown(conn->fd, 1);
	    FD_CLR(conn->fd, &selstate->wfds);
	    /* Q: How do we detect failures to send the remaining data
	       to the remote side, since we're in non-blocking mode?
	       Will we always get errors on the reading side?  */
	    dfprintf((stderr, "switching fd %d to READING\n", conn->fd));
	    conn->state = READING;
	    conn->bufsizebytes_read = 0;
	}
	return 0;

    case READING:
	if (conn->bufsizebytes_read == 4) {
	    /* Reading data.  */
	    dfprintf((stderr, "reading %ld bytes of data from fd %d\n",
		      (long) conn->iov[0].iov_len, conn->fd));
	    nread = read(conn->fd, conn->iov[0].iov_base,
			 conn->iov[0].iov_len);
	    if (nread <= 0) {
		e = nread ? SOCKET_ERRNO : ECONNRESET;
		free(conn->buf);
		conn->buf = 0;
		goto kill_conn;
	    }
	    iov_advance(conn->iov, nread);
	    if (conn->iov[0].iov_len == 0) {
		/* We win!  */
		return 1;
	    }
	} else {
	    /* Reading length.  */
	    nread = read(conn->fd,
			 conn->bufsizebytes + conn->bufsizebytes_read,
			 4 - conn->bufsizebytes_read);
	    if (nread < 0) {
		e = SOCKET_ERRNO;
		goto kill_conn;
	    }
	    conn->bufsizebytes_read += nread;
	    if (conn->bufsizebytes_read == 4) {
		unsigned long len;
		len = conn->bufsizebytes[0];
		len = (len << 8) + conn->bufsizebytes[1];
		len = (len << 8) + conn->bufsizebytes[2];
		len = (len << 8) + conn->bufsizebytes[3];
		dfprintf((stderr, "received length on fd %d is %lu\n",
			  conn->fd, len));
		/* Arbitrary 1M cap.  */
		if (len > 1 * 1024 * 1024) {
		    e = E2BIG;
		    goto kill_conn;
		}
		conn->bufsize = conn->iov[0].iov_len = len;
		conn->buf = conn->iov[0].iov_base = malloc(len);
		dfprintf((stderr, "allocated %lu byte buffer at %p\n",
			  len, conn->buf));
		if (conn->iov[0].iov_base == 0) {
		    e = errno;
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
service_fds (struct select_state *selstate,
	     struct conn_state *conns, size_t n_conns, int *winning_conn)
{
    int e, selret;
    struct select_state sel_results;

    e = 0;
    while (selstate->nfds > 0
	   && (e = call_select(selstate, &sel_results, &selret)) == 0) {
	int i;

	dfprintf((stderr, "service_fds examining results, selret=%d\n",
		  selret));

	if (selret == 0)
	    /* Timeout, return to caller.  */
	    return 0;

	/* Got something on a socket, process it.  */
	for (i = 0; i <= selstate->max && selret > 0; i++) {
	    int can_read, can_write;
	    if (conns[i].fd == INVALID_SOCKET)
		continue;
	    can_read = FD_ISSET(conns[i].fd, &sel_results.rfds);
	    can_write = FD_ISSET(conns[i].fd, &sel_results.wfds);
	    if (!can_read && !can_write)
		continue;

	    selret--;
	    if (service_tcp_fd(&conns[i], selstate, can_read, can_write)) {
		dfprintf((stderr, "service_tcp_fd says we're done\n"));
		*winning_conn = i;
		return 1;
	    }
	}
    }
    if (e != 0) {
	dfprintf((stderr, "select returned %s\n", strerror(e)));
	*winning_conn = -1;
	return 1;
    }
    return 0;
}

krb5_error_code
krb5int_sendto_tcp (krb5_context context, const krb5_data *message,
		    const struct addrlist *addrs, krb5_data *reply)
{
    int i;
    krb5_error_code retval;
    struct conn_state *conns;
    size_t n_conns, host;
    struct select_state select_state;
    struct timeval now;
    int winning_conn = -1, e = 0;
    unsigned char message_len_buf[4];

    n_conns = addrs->naddrs;
    conns = malloc(n_conns * sizeof(struct conn_state));
    if (conns == NULL) {
	return ENOMEM;
    }
    for (i = 0; i < n_conns; i++) {
	memset(&conns[i], 0, sizeof(conns[i]));
	conns[i].fd = INVALID_SOCKET;
    }

    select_state.max = 0;
    select_state.nfds = 0;
    FD_ZERO(&select_state.rfds);
    FD_ZERO(&select_state.wfds);

    message_len_buf[0] = (message->length >> 24) & 0xff;
    message_len_buf[1] = (message->length >> 16) & 0xff;
    message_len_buf[2] = (message->length >>  8) & 0xff;
    message_len_buf[3] =  message->length        & 0xff;

    /* Set up connections.  */
    for (host = 0; host < n_conns; host++) {
	if (addrs->addrs[host]->ai_socktype != SOCK_STREAM)
	    continue;
	/* Send to the host, wait timeout seconds for a response,
	   then move on. */
	if (start_tcp_connection (&conns[host], addrs->addrs[host]))
	    continue;
	conns[host].iov[0].iov_base = (char *) message_len_buf;
	conns[host].iov[0].iov_len = 4;
	conns[host].iov[1].iov_base = message->data;
	conns[host].iov[1].iov_len = message->length;
	    
	FD_SET(conns[host].fd, &select_state.rfds);
	FD_SET(conns[host].fd, &select_state.wfds);
	if (select_state.max <= conns[host].fd)
	    select_state.max = conns[host].fd + 1;
	select_state.nfds++;

	if (gettimeofday(&now, 0)) {
	    retval = errno;
	    dperror("gettimeofday");
	    goto egress;
	}
	select_state.end_time = now;
	select_state.end_time.tv_sec++;
	e = service_fds(&select_state, conns, host+1, &winning_conn);
	if (e)
	    break;
    }

    if (select_state.nfds == 0) {
	/* No addresses?  */
	free(conns);
	return KRB5_KDC_UNREACH;
    }
    if (e == 0) {
	if (gettimeofday(&now, 0)) {
	    retval = errno;
	    dperror("gettimeofday");
	    goto egress;
	}
	select_state.end_time = now;
	select_state.end_time.tv_sec += 30;
	e = service_fds(&select_state, conns, n_conns, &winning_conn);
    }
    if (e == 0 || winning_conn < 0) {
	retval = KRB5_KDC_UNREACH;
	goto egress;
    }
    /* Success!  */
    reply->data = conns[winning_conn].buf;
    reply->length = conns[winning_conn].bufsize;
    dfprintf((stderr, "returning %lu bytes in buffer %p\n",
	      (unsigned long) reply->length, reply->data));
    retval = 0;
    conns[winning_conn].buf = 0;
egress:
    for (i = 0; i < n_conns; i++) {
	if (conns[i].fd != INVALID_SOCKET)
	    close(conns[i].fd);
	if (conns[i].buf != 0)
	    free(conns[i].buf);
    }
    free(conns);
    return retval;
}
#endif
