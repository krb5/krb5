/*
 * macsock.c
 *
 * Macintosh socket implementation using MacTCP.
 *
 * This only implements what's needed for Cygnus Kerberos -- a warped
 * subset of UDP.
 *
 * Written by John Gilmore, Cygnus Support, June 1994.
 * Adapted from:
	Interface into the UDP class.
	Written by Timothy Miller for Brown University.
 */

/* C includes */
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Mac includes */
#include <Memory.h>
#include <Devices.h>
#include <errno.h>		/* For ENOMEM */

#ifndef ENOMEM			/* Think C <errno.h> doesn't have ENOMEM */
#define	ENOMEM	ENOSPC
#endif

/* Our own include file */
#include "macsock.h"

/* Kerberos:source:lib:kerb - MacTCP headers from KClient */
#include "MacTCPCommonTypes.h"
#include "UDPPB.h"
#include "AddressXlation.h"		/* MacTCP Domain name resolver decls */

/* This WinSock-ism is just too ugly to use everywhere.  */
#define	SOCKET_SET_ERRNO	WSASetLastError

/* Description of our WinSock implementation... */
struct WSAData macsock_data = {
	0x0101,		/* wVersion = 1.1 */
	0x0101,		/* wHighVersion = 1.1 */
	"Mac Sockets implemented on top of MacTCP, by John Gilmore of\
Cygnus Support (email info@cygnus.com).",
	"It only implements a small subset of UDP for now.",
	107,		/* iMaxSockets, arbitrary number */
	UDPbuflen,	/* iMaxUDPDg, max datagram size */
	0			/* lpVendorInfo, nonexistent */
};
	
/* This variable implements a kludge in which select() always says that
   sockets are ready for I/O, but recvfrom() actually implements the
   timeout that select() had requested.  This hack happens to work
   for Kerberos, which is all that we care about right now.  */
static struct timeval last_timeout;


/* Forward declarations of static functions */

static pascal void	DNRresultproc(struct hostInfo *hinfo, char *userdata);


/* Start using sockets */
int
WSAStartup(WORD wVersionRequested, WSADATA *data)
{
	if (LOBYTE (wVersionRequested) < 1 ||
	    (LOBYTE (wVersionRequested) == 1 && HIBYTE (wVersionRequested) < 1))
		return WSAVERNOTSUPPORTED;
	if (data)
		*data = macsock_data;
	return 0;
}

/* Finish using sockets */
int
WSACleanup()
{
	return 0;
}

/* Get a particular socket */
SOCKET
socket(af, type, protocol)
	int af;
	int type;
	int protocol;
{
	SOCKET  theUDP;
	short	refNum;
	UDPiopb		pb;
	OSErr	err;

	if (af != AF_INET) {
		SOCKET_SET_ERRNO (EINVAL);
		return INVALID_SOCKET;
	}
	if (type != SOCK_DGRAM) {
		SOCKET_SET_ERRNO (EINVAL);
		return INVALID_SOCKET;
	}
	if (protocol != 0) {
		SOCKET_SET_ERRNO (EINVAL);
		return INVALID_SOCKET;
	}

	theUDP = malloc (sizeof (*theUDP));
	if (theUDP == 0) {
		SOCKET_SET_ERRNO (ENOMEM);
		return INVALID_SOCKET;
	}

	err = OpenDriver( "\p.IPP", &refNum );
	if (err) {
		free (theUDP);
		SOCKET_SET_ERRNO (EIO);
		return INVALID_SOCKET;
	}
	theUDP->fMacTCPRef = refNum;

	/* Set up param blocks and create the socket (called a 
	   stream by MacTCP).  */
	pb.ioCRefNum					= theUDP->fMacTCPRef;
	pb.csCode						= UDPCreate;
	pb.csParam.create.rcvBuff		= theUDP->fRecvBuf;
	pb.csParam.create.rcvBuffLen	= UDPbuflen;
	pb.csParam.create.notifyProc	= NULL;
	pb.csParam.create.localPort		= 0;

	err = PBControl( (ParamBlockRec *) &pb, false );
	if (err) {
		free (theUDP);
		SOCKET_SET_ERRNO (EIO);
		return INVALID_SOCKET;
	}
	theUDP->fStream = (unsigned long)pb.udpStream;

	return theUDP;
}

/* Finish using a particular socket.  */
int
closesocket (theUDP)
	SOCKET theUDP;
{
	UDPiopb		pb;

	if (theUDP->fStream) {
		pb.ioCRefNum	= theUDP->fMacTCPRef;
		pb.csCode		= UDPRelease;
		pb.udpStream	= (StreamPtr) theUDP->fStream;

		(void) PBControl( (ParamBlockRec *) &pb, false );
	}

	free(theUDP);
	return 0;
}


/* Bind a socket to a particular address.
   In our case, this is just a no-op for bug-compatability with
   the FTP Software WINSOCK library.  */
int
bind (s, name, namelen)
	SOCKET s;
	const struct sockaddr *name;
	int namelen;
{
	if (name->sin_family != AF_INET) {
		SOCKET_SET_ERRNO (EINVAL);
		return SOCKET_ERROR;
	}
#if 0
	if (namelen != sizeof (struct sockaddr_in)) {
		SOCKET_SET_ERRNO (EINVAL);
		return SOCKET_ERROR;
	}
	if (name->sin_addr.s_addr != INADDR_ANY) {
		SOCKET_SET_ERRNO (EINVAL);
		return SOCKET_ERROR;
	}
#endif
	/* OK, then, it's a no-op.  */
	s - s;		/* lint */
	return 0;
}


/* Send a packet to a UDP peer.  */
int
sendto (theUDP, buf, len, flags, to_param, tolen)
	SOCKET theUDP;
	const char *buf;
	const int len; 
	int flags;
	const struct sockaddr *to_param;
	int tolen;
{
	OSErr		err;
    /* really 1 wds + extra space for terminating null */
	wdsEntry	wds[2];
	UDPiopb		pb;
	struct sockaddr_in *to = (struct sockaddr_in *)to_param;

	if (tolen != sizeof (struct sockaddr_in)) {
		SOCKET_SET_ERRNO (EINVAL);
		return SOCKET_ERROR;
	}
	if (to->sin_family != AF_INET) {
		SOCKET_SET_ERRNO (EINVAL);
		return SOCKET_ERROR;
	}

	wds[0].length	= len;
	wds[0].ptr		= (char *) buf;
	wds[1].length	= 0;

	pb.ioCRefNum				= theUDP->fMacTCPRef;
	pb.csCode					= UDPWrite;
	pb.udpStream				= (StreamPtr) theUDP->fStream;
	pb.csParam.send.remotePort	= to->sin_port;
	pb.csParam.send.wdsPtr		= (Ptr) wds;
	pb.csParam.send.checkSum	= 1;			// TRUE
	pb.csParam.send.sendLength	= 0;			// reserved
	pb.csParam.send.remoteHost	= to->sin_addr.s_addr;

	err = PBControl( (ParamBlockRec *) &pb, false );
	if (err != noErr) {
		SOCKET_SET_ERRNO (EIO);
		return SOCKET_ERROR;
	}
	return len;
}

/* Select for sockets that are ready for I/O.
   This version just remembers the timeout for a future receive...
   It always reports that one socket is ready for I/O.
 */
int
select (nfds, readfds, writefds, exceptfds, timeout)
	int nfds;
	fd_set *readfds;
	fd_set *writefds;
	fd_set *exceptfds;
	const struct timeval *timeout;
{
	if (timeout)
		last_timeout = *timeout;
	return 1;	/* Claim that a single FD is ready */
	/* Note that readfd, writefds, and exceptfds still have all
	   of their current values, indicating that they're all ready
 	   for I/O.  */
}


/* Receive a packet from a UDP peer.  */
int
recvfrom (theUDP, buf, len, flags, from_param, fromlen)
	SOCKET theUDP;	
	char *buf;
	int len; 
	int flags;
	struct sockaddr *from_param;
	int *fromlen;
{
	OSErr		err;
	UDPiopb		pb;
	int			packet_len;
	struct sockaddr_in *from = (struct sockaddr_in *)from_param;
	
	if (*fromlen < sizeof (*from)) {
		SOCKET_SET_ERRNO (EINVAL);
		return SOCKET_ERROR;
	}

	pb.ioCRefNum						= theUDP->fMacTCPRef;
	pb.csCode							= UDPRead;
	pb.udpStream						= (StreamPtr) theUDP->fStream;
	pb.csParam.receive.timeOut			= last_timeout.tv_sec;
	pb.csParam.receive.secondTimeStamp	= 0;			// reserved

	err = PBControl( (ParamBlockRec *) &pb, false );
	if( err ) {
		SOCKET_SET_ERRNO (EIO);
		return SOCKET_ERROR;
	}

	packet_len = pb.csParam.receive.rcvBuffLen;
	if( len > packet_len )
		len = packet_len;	/* only move as much as we got */
	BlockMove( pb.csParam.receive.rcvBuff, buf, len );
	*fromlen = sizeof (*from);
	from->sin_family = AF_INET;
	from->sin_port = pb.csParam.receive.remotePort;
	from->sin_addr.s_addr = pb.csParam.receive.remoteHost;

	if( pb.csParam.receive.rcvBuffLen ) {
		pb.csCode = UDPBfrReturn;
		err = PBControl( (ParamBlockRec *) &pb, false );
	}

	if (len < packet_len) {
		/* Only got first part of packet, rest was dropped. */
		SOCKET_SET_ERRNO (EMSGSIZE);
		return SOCKET_ERROR;
	}
	return len;
}



/*
	Interface UNIX routine inet_ntoa with mac equivalent.

	The input argument is a struct containing the internet address.
	struct type defined in config-mac.h

	The routine inet_ntoa() returns a pointer to a string in the
	base 256 notation ``d.d.d.d'' 
*/
 
 
char* 
inet_ntoa(struct in_addr ina) {
	OSErr err;
#define	max_addr_str 16
	char addrStr[max_addr_str];

	err = AddrToStr(ina.s_addr, addrStr);
	return addrStr;

}

/* Static variables which provide space for the last result from getXbyY.  */

static struct hostInfo		host;
static char *				ipaddr_ptrs[NUM_ALT_ADDRS+1];
static struct hostent		result;
	
/*
   Performs a domain name resolution of host, returning an IP address for it,
   or 0 if any error occurred. 
	   
   FIXME -- this routine has the potential to go asynchronous, but it
   loops until the asynchronous call to MacTCP finishes.  
 */
	
struct hostent *
gethostbyname (char *hostname)
{
	OSErr						err;
	char						done = false;
	int							i;
		
	if (err = OpenResolver(NULL))
		return(0);	// make sure resolver is open
	err = StrToAddr(hostname, &host, DNRresultproc, &done);
	
	if (err == cacheFault) {
		while(!done) ;			/* LOOP UNTIL CALLBACK IS RUN */
		err = host.rtnCode;		/* Pick up final result code */
		}
	
	if (err != noErr) {
		return 0;
		}
	
	/* Build result in hostent structure, which we will return to caller.  */
	
	result.h_name = host.cname;
	result.h_aliases = 0;			/* We don't know about aliases.  */
	result.h_addrtype = AF_INET;
	result.h_length = sizeof (host.addr[0]);	/* Length of each address */
	result.h_addr_list = ipaddr_ptrs;
    for (i = 0; i < NUM_ALT_ADDRS; i++)
		if (host.addr[i] != 0)				/* Assume addrs terminated with 0 addr */
			ipaddr_ptrs[i] = (char*) &host.addr[i];		/* Point at good IP addresses */
		else
			break;					/* Quit when we see first zero address */
	ipaddr_ptrs[i] = 0;
	
	return &result;
}

/* Does a reverse DNS lookup of addr, to find the canonical name of its host.
   FIXME, set errno for failures.  */

struct hostent *
gethostbyaddr (char *addr, int len, int type)
{
	OSErr				err;
	char				done = false;
	ip_addr				macaddr;
	
	if (type != AF_INET)
		return 0;			/* We only do Internet addresses */
	if (len != sizeof (ip_addr))
		return 0;			/* We only handle IP addrs *this* long... */
	memcpy ((void *)&macaddr, (void *)addr, (size_t)len);
		
	if (err = OpenResolver(NULL))
		return 0;	// make sure resolver is open
	err = AddrToName(macaddr, &host, DNRresultproc, &done);
	
	if (err == cacheFault) {
		while(!done) ;			/* LOOP UNTIL CALLBACK IS RUN */
		err = host.rtnCode;		/* Pick up final result code */
		}
	
	if (err != noErr) {
		/* Set errno? FIXME.  */
		return 0;
		}

	/* Build result in hostent structure, which we will return to caller.  */
	
	result.h_name = host.cname;
	result.h_aliases = 0;			/* We don't know about aliases.  */
	result.h_addrtype = AF_INET;
	result.h_length = sizeof (host.addr[0]);	/* Length of each address */
	result.h_addr_list = 0;		/* MacTCP doesn't give us this info on addr->name */
	
	return &result;
}

/* Tell calling program that the asynchronous operation has finished.
   FIXME, this will require significant work if we support async calls to
   Kerberos in the future.  */
static pascal void
DNRresultproc(struct hostInfo *hinfo, char *userdata)
{
	*userdata = true;
}


int
gethostname(char *name, int namelen)
{
	return -1;
}

#if 0
/* FIXME:  THIS WAS A STAB AT GETHOSTNAME, which I abandoned for lack of need,
   and since the required header files didn't seem to be handy.
						-- gnu@cygnus.com  june94 */
/*
 * gethostname
 *
 * Gets our own host name, by getting our IP address and asking what name
 * corresponds.  There seems to be no better way in MacTCP to do this.
 */
 int
 gethostname(name, namelen)
 	char *name;
	int namelen;
{
	ip_addr ourAddress;
	SOCKET sock;
	struct IPParamBlock pb;
	struct hostent *host;
	struct sockaddr_in hostaddr;
	
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (!sock)
		return -1;
	pb.ioCRefNum	= sock->fMacTCPRef;
	pb.csCode		= ipctlGetAddr;
	err = PBControl( (ParamBlockRec *) &pb, false );
	if (err) {
		free (theUDP);
		SOCKET_SET_ERRNO (EIO);
		return -1;
	}
	

	pb.csParam.xxxx
	
	host = gethostbyaddr (&hostaddr, sizeof (hostaddr), AF_INET);
	if (!host)
		return -1;
	len = strlen (host->h_name);
	if (len > namelen)
		return -1;
	memcpy (name, host->h_name, len+1);
	return 0;
}

#endif
