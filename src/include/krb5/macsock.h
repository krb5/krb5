/*
 * Mac interface compatible with WinSock and Unix Sockets.
 * 
 * Implemented by John Gilmore, Cygnus Support, June 1994.
 *
 * Derived from:
 *
	Interface into the UDP class.
	Written by Timothy Miller for Brown University.
	
	This class is extremely sketchy and not meant for general use.
	It's only here because I need a machine independant interface
	for UDP for internal use by kerberos. If you need to use udp to
	do anything serious, be my guest and rewrite this! (Just be
	sure to update the kerberos files send_to_kdc.cp and
	time_stuff.cp if you change the interface.)
 *
 * This interface only implements a warped subset of sockets, suitable only
 * for a Kerberos client's communication with its Key Distribution Centers.
 */

#ifndef macsock_h
#define macsock_h

#include <Sockets.h>
#include <ErrorLib.h>
#include <netdb.h>

/* Handle ANSI C versus traditional C */
#ifndef __STDC__
#define const
#define volatile
#define signed
#ifndef PROTOTYPE
#define PROTOTYPE(p) ()
#endif
#else
#ifndef PROTOTYPE
#define PROTOTYPE(p) p
#endif
#endif

#define	WORD	short
#define	LOBYTE(x)	 ((x)       & 0xFF)
#define	HIBYTE(x)	(((x) >> 8) & 0xFF)

/* Error codes */
/* FIXME -- picked at random */
/*#define	WSAVERNOTSUPPORTED	14563	/* WinSock version not supported */
/*#define	EMSGSIZE		14567	/* Received packet truncated */
/*#define	WSAEINTR		14568	/* Interrupted system call */
/*#define	ECONNABORTED		14569	/* Interrupted system call */

/* Socket functions as defined by SocketsLib */
#define closesocket  socket_close
#define connect      socket_connect
#define bind         socket_bind

#define sendto       socket_sendto
#define send         socket_send
#define recvfrom     socket_recvfrom
#define recv         socket_recv

#define select       socket_select

#define getsockname  socket_getsockname
#define getpeername  socket_getpeername

#define SOCKET_READ  socket_read
#define SOCKET_WRITE socket_write

typedef int SOCKET;
/*
 * Compatability with WinSock calls on MS-Windows...
 */
 
#define	SOCKET_INITIALIZE()	()
#define	SOCKET_CLEANUP()	
 
#define	INVALID_SOCKET	    (-1L)
#define	SOCKET_ERROR	    (-1)
#define SOCKET_EINTR		EINTR
#define WSAECONNABORTED     kECONNABORTEDErr

#define MAXHOSTNAMELEN      MAXHOSTNAMESIZE

#define	SOCKET_NFDS(f)		(FD_SETSIZE)	/* select()'s first arg is maxed out */

#define	WSAGetLastError()	(GetMITLibError())
#define	WSASetLastError(x)	(SetMITLibError(x))
#define	SOCKET_ERRNO		(GetMITLibError())
#define	SOCKET_SET_ERRNO(x)	(SetMITLibError(x))

#define local_addr_fallback_kludge() (0)


#endif /* macsock_h */
