/*
 * Copyright 1990,1991,1994,1995 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Sockets interface header file
 */

#ifdef _MSDOS

#include <winsock.h>

/* Some of our own infrastructure where the WinSock stuff was too hairy
   to dump into a clean Unix program...  */

#define SOCKET_INITIALIZE()     win_socket_initialize()
#define SOCKET_CLEANUP()        WSACleanup()
#define SOCKET_ERRNO            (WSAGetLastError())
#define SOCKET_SET_ERRNO(x)     (WSASetLastError (x))
#define SOCKET_NFDS(f)          (0)     /* select()'s first arg is ignored */
#define SOCKET_READ(fd, b, l)   (recv(fd, b, l, 0))
#define SOCKET_WRITE(fd, b, l)  (send(fd, b, l, 0))
#define SOCKET_EINTR            WSAEINTR

int win_socket_initialize();

#else /* not _MSDOS */

/* If this source file requires it, define struct sockaddr_in
   (and possibly other things related to network I/O).  */

#ifdef HAVE_MACSOCK_H		/* Sockets stuff differs on Mac */
#include "macsock.h"		/* Macintosh sockets emulation library */

/* Some of our own infrastructure where the WinSock stuff was too hairy
   to dump into a clean Unix program...  */

#define	SOCKET_INITIALIZE()	(WSAStartup(0x0101, (WSADATA *)0))
#define	SOCKET_CLEANUP()	(WSACleanup())
#define	SOCKET_ERRNO		(WSAGetLastError())
#define	SOCKET_SET_ERRNO(x)	(WSASetLastError(x))
#define	SOCKET_NFDS(f)		(0)	/* select()'s first arg is ignored */
#define SOCKET_READ(fd, b, l)	(recv(fd, b, l, 0))
#define SOCKET_WRITE(fd, b, l)	(send(fd, b, l, 0))
#define SOCKET_EINTR		WSAEINTR

#else  /* ! HAVE_MACSOCK_H */	/* Sockets stuff for Unix machines */

#include <netinet/in.h>		/* For struct sockaddr_in and in_addr */
#include <arpa/inet.h>		/* For inet_ntoa */
#include <netdb.h>		/* For struct hostent, gethostbyname, etc */
#include <sys/param.h>		/* For MAXHOSTNAMELEN */
#include <sys/socket.h>		/* For SOCK_*, AF_*, etc */
#include <sys/time.h>		/* For struct timeval */
#include <net/if.h>		/* For struct ifconf, for localaddr.c */

/*
 * Compatability with WinSock calls on MS-Windows...
 */
#define	SOCKET		unsigned int
#define	INVALID_SOCKET	((SOCKET)~0)
#define	closesocket	close
#define	ioctlsocket	ioctl
#define	SOCKET_ERROR	(-1)

/* Some of our own infrastructure where the WinSock stuff was too hairy
   to dump into a clean Unix program...  */

#define	SOCKET_INITIALIZE()	(0)	/* No error (or anything else) */
#define	SOCKET_CLEANUP()	/* nothing */
#define	SOCKET_ERRNO		errno
#define	SOCKET_SET_ERRNO(x)	(errno = (x))
#define SOCKET_NFDS(f)		((f)+1)	/* select() arg for a single fd */
#define SOCKET_READ		read
#define SOCKET_WRITE		write
#define SOCKET_EINTR		EINTR

#endif /* HAVE_MACSOCK_H */

#endif /* _MSDOS */
