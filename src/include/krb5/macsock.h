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
#define	WSAVERNOTSUPPORTED	14563	/* WinSock version not supported */
#define	EMSGSIZE		14567	/* Received packet truncated */
#define	WSAEINTR		14568	/* Interrupted system call */
#define	ECONNABORTED		14569	/* Interrupted system call */


/* Struct for initializing the socket library */
struct WSAData {
	WORD	wVersion;
	WORD	wHighVersion;
#define	WSADESCRIPTION_LEN	256
	char	szDescription[WSADESCRIPTION_LEN+1];
#define	WSASYSSTATUS_LEN	256
	char	szSystemStatus[WSASYSSTATUS_LEN+1];
	unsigned short	iMaxSockets;
	unsigned short	iMaxUdpDg;
	char 	*lpVendorInfo;
};

typedef struct WSAData WSADATA;

/*
 * Internet address.  New code should use only the s_addr field.
 */
struct in_addr {
	unsigned long s_addr;
};


/*
 * Socket address, internet style.
 */
struct sockaddr_in {
	short	sin_family;
	unsigned short	sin_port;
	struct	in_addr sin_addr;
	char	sin_zero[8];
};

/* Socket address, other styles */
#define	sockaddr sockaddr_in
#define	sa_family sin_family


/* The socket data structure itself.   */
struct socket {
	short		fMacTCPRef;		/* refnum of MacTCP driver */
	short		fType;			/* UDP == SOCK_DGRAM or TCP == SOCK_STREAM Socket */
	unsigned long	fStream;		/* MacTCP socket/stream */
	struct sockaddr_in connect_addr;	/* Address from connect call */
#	define		UDPbuflen	4096
	char		fRecvBuf[UDPbuflen];	/* receive buffer area */
};

typedef struct socket *SOCKET;

/*
 * Host name<->address mapping entries
 */
struct    hostent {
    char *h_name;  /* official name of host */
    char **h_aliases;   /* alias list */
    int  h_addrtype;    /* address type */
    int  h_length; /* length of address */
    char **h_addr_list; /* list of addresses from name server */
#if 0
#define	h_addr	h_addr_list[0]	/* address, for backward compatiblity */
#endif
#define	h_addr	h_addr_list	/* address, for backward compatiblity */
};

/*
 * Service name<->port mapping
 */
struct	servent {
	char	*s_name;	/* official service name */
	char	**s_aliases;	/* alias list */
	int	s_port;		/* port # */
	char	*s_proto;	/* protocol to use */
};

#ifndef _MWERKS
/* Timeout values */
struct timeval {
	long tv_sec;			/* Seconds */
	long tv_usec;			/* Microseconds */
};
#endif

/* True Kludge version of select argument fd_set's */
typedef int		fd_set;
#define	FD_ZERO(x)	0
#define	FD_CLEAR(x)	/* nothing */
#define	FD_SET(fd,x)	/* nothing */
#define	FD_ISSET(fd, x)	1

/* Other misc constants */
#define	MAXHOSTNAMELEN	512	/* Why be stingy? */
#define	SOCK_DGRAM	2		/* Datagram socket type */
#define	AF_INET	2			/* Internet address family */
#define PF_INET AF_INET
#define	INADDR_ANY	((unsigned long)0)	/* Internet addr: any host */
#define SOCK_STREAM 3		/* Stream socket type */


/* Start using sockets */
extern int
WSAStartup PROTOTYPE ((WORD version, struct WSAData *));

/* Finish using sockets */
extern int
WSACleanup PROTOTYPE ((void));

/* Get a particular socket */
extern SOCKET
socket PROTOTYPE ((int af, int type, int protocol));

/* Finish using a particular socket.  */
extern int
closesocket PROTOTYPE ((SOCKET theUDP));

/* Bind a socket to a particular address.
   In our case, this is just a no-op for bug-compatability with
   the FTP Software WINSOCK library.  */
extern int
bind PROTOTYPE ((SOCKET s, const struct sockaddr *name, int namelen));

/* Send a packet to a UDP peer.  */
extern int
sendto PROTOTYPE ((SOCKET theUDP, const char *buf, const int len, int flags,
	const struct sockaddr *to, int tolen));

/* Send a packet to a connected UDP peer.  */
extern int
send PROTOTYPE ((SOCKET theUDP, const char *buf, const int len, int flags));

/* Select for sockets that are ready for I/O.
   This version just remembers the timeout for a future receive...
   It always reports that one socket is ready for I/O.  */
extern int
select PROTOTYPE ((int nfds, fd_set *readfds, fd_set *writefds,
		   fd_set *exceptfds, const struct timeval *timeout));

/* Receive a packet from a UDP peer.  */
extern int
recvfrom PROTOTYPE ((SOCKET theUDP, char *buf, int len, int flags,
		     struct sockaddr *from, int *fromlen));

/* Receive a packet from a connected UDP peer.  */
extern int
recv PROTOTYPE ((SOCKET theUDP, char *buf, int len, int flags));

extern char *
inet_ntoa PROTOTYPE ((struct in_addr ina));

extern struct hostent *
gethostbyname PROTOTYPE ((char *));

extern struct hostent *
gethostbyaddr PROTOTYPE ((char *addr, int len, int type));

extern struct hostent *
getmyipaddr PROTOTYPE ((void));

extern int
getsockname PROTOTYPE((SOCKET, struct sockaddr_in *, int *));

/* Bypass a few other functions we don't really need. */

#define	getservbyname(name,prot)	0

/* Macs operate in network byte order (big-endian).  */
#define	htonl(x)	(x)
#define	htons(x)	(x)
#define	ntohl(x)	(x)
#define	ntohs(x)	(x)

/*
 * Compatability with WinSock calls on MS-Windows...
 */
#define	INVALID_SOCKET	((SOCKET)~0)
#define	SOCKET_ERROR	(-1)
#define	WSAGetLastError()	(errno)
#define	WSASetLastError(x)	(errno = (x))

extern int errno;
