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

#include "k5-int.h"
#ifdef	HAVE_MACSOCK_H

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

/* MacTCP headers from Apple */
#include "MacTCPCommonTypes.h"
#include "UDPPB.h"
#include "TCPPB.h"
#include "AddressXlation.h"		/* MacTCP Domain name resolver decls */
#include "GetMyIPAddr.h"		/* Like it sez... */

typedef union {
	UDPiopb		udppb;
	TCPiopb		tcppb;
} sockunion;

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

#define kMaxIPPOpenTries 3
	
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
//	UDPiopb		pb;
	sockunion	pb;
	OSErr	err;
	int		tries;

	if (af != AF_INET) {
		SOCKET_SET_ERRNO (EINVAL);
		return INVALID_SOCKET;
	}
	if (type != SOCK_DGRAM && type != SOCK_STREAM) {
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

	err = -1;
	for(tries=0;tries<kMaxIPPOpenTries && err != noErr;tries++)
	{
		err = OpenDriver( "\p.IPP", &refNum );
	}
	if (err) {
		free (theUDP);
		SOCKET_SET_ERRNO (EIO);
		return INVALID_SOCKET;
	}
	theUDP->fMacTCPRef = refNum;
	theUDP->fType = type;
	switch(theUDP->fType)
	{
	case SOCK_DGRAM:
		/* Set up param blocks and create the socket (called a 
		   stream by MacTCP).  */
		pb.udppb.ioCRefNum					= theUDP->fMacTCPRef;
		pb.udppb.csCode						= UDPCreate;
		pb.udppb.csParam.create.rcvBuff		= theUDP->fRecvBuf;
		pb.udppb.csParam.create.rcvBuffLen	= UDPbuflen;
		pb.udppb.csParam.create.notifyProc	= NULL;
		pb.udppb.csParam.create.localPort		= 0;
	
		err = PBControl( (ParamBlockRec *) &pb.udppb, false );
		if (err) {
			free (theUDP);
			SOCKET_SET_ERRNO (EIO);
			return INVALID_SOCKET;
		}
		theUDP->fStream = (unsigned long)pb.udppb.udpStream;
	
		theUDP->connect_addr.sin_family = 0;
		theUDP->connect_addr.sin_port = 0;
		theUDP->connect_addr.sin_addr.s_addr = 0;
		break;

	case SOCK_STREAM:
		pb.tcppb.ioCRefNum = theUDP->fMacTCPRef;
		pb.tcppb.csCode = TCPCreate;
		pb.tcppb.csParam.create.rcvBuff = theUDP->fRecvBuf;
		pb.tcppb.csParam.create.rcvBuffLen = UDPbuflen;
		pb.tcppb.csParam.create.notifyProc = NULL;
		err = PBControl((ParamBlockRec *)&pb,false);
		if (err) {
			free(theUDP);
			SOCKET_SET_ERRNO (EIO);
			return INVALID_SOCKET;
		}
		theUDP->fStream = (unsigned long)pb.tcppb.tcpStream;
	
		theUDP->connect_addr.sin_family = 0;
		theUDP->connect_addr.sin_port = 0;
		theUDP->connect_addr.sin_addr.s_addr = 0;
		break;
	}
	return theUDP;
}

/* Finish using a particular socket.  */
int
closesocket (theUDP)
	SOCKET theUDP;
{
//	UDPiopb		pb;
	sockunion	pb;

	switch(theUDP->fType)
	{
	case SOCK_DGRAM:
		if (theUDP->fStream) {
			pb.udppb.ioCRefNum	= theUDP->fMacTCPRef;
			pb.udppb.csCode		= UDPRelease;
			pb.udppb.udpStream	= (StreamPtr) theUDP->fStream;
	
			(void) PBControl( (ParamBlockRec *) &pb.udppb, false );
		}
		break;
	case SOCK_STREAM:
		if (theUDP->fStream) {
			pb.tcppb.ioCRefNum	= theUDP->fMacTCPRef;
			pb.tcppb.csCode		= TCPRelease;
			pb.tcppb.tcpStream	= (StreamPtr) theUDP->fStream;
	
			(void) PBControl( (ParamBlockRec *) &pb.tcppb, false );
		}
		break;
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

/* On BSD systems, a connected UDP socket will get connection
   refused and net unreachable errors while an unconnected
   socket will time out, so K5 uses connect, send, recv instead of
   sendto, recvfrom.  We happily fake this too...   */

int
connect (s, addr, tolen)
	SOCKET s;
	struct sockaddr *addr;
	int tolen;
{
	sockunion pb;
	OSErr err;
	
	if (tolen != sizeof (struct sockaddr_in)) {
		SOCKET_SET_ERRNO (EINVAL);
		return SOCKET_ERROR;
	}
	if (addr->sin_family != AF_INET) {
		SOCKET_SET_ERRNO (EINVAL);
		return SOCKET_ERROR;
	}

	s->connect_addr = *addr;		/* Save the connect address */
	switch(s->fType)
	{
	case SOCK_DGRAM:
		break;
	case SOCK_STREAM:
		pb.tcppb.ioCRefNum = s->fMacTCPRef;
		pb.tcppb.csCode = TCPActiveOpen;
		pb.tcppb.csParam.open.validityFlags = timeoutValue | timeoutAction;
		pb.tcppb.csParam.open.ulpTimeoutValue = 60 /* seconds */;
		pb.tcppb.csParam.open.ulpTimeoutAction = 1 /* 1:abort 0:report */;
		pb.tcppb.csParam.open.commandTimeoutValue = 0;
		pb.tcppb.csParam.open.remoteHost = addr->sin_addr.s_addr;
		pb.tcppb.csParam.open.remotePort = addr->sin_port;
		pb.tcppb.csParam.open.localHost = 0;
		pb.tcppb.csParam.open.localPort = 0; /* we'll get the port back later */
		pb.tcppb.csParam.open.dontFrag = 0;
		pb.tcppb.csParam.open.timeToLive = 0;
		pb.tcppb.csParam.open.security = 0;
		pb.tcppb.csParam.open.optionCnt = 0;
		pb.tcppb.tcpStream = s->fStream;
		err = PBControl((ParamBlockRec *)&pb.tcppb,false);
		if (err) {
			SOCKET_SET_ERRNO (EINVAL);
			return SOCKET_ERROR;
		}
		
		s->connect_addr.sin_addr.s_addr = pb.tcppb.csParam.open.localHost;
		s->connect_addr.sin_port = pb.tcppb.csParam.open.localPort;

		break;
	}
	return 0;
}

/* Receive a packet from a UDP peer.  */
int
recv (theUDP, buf, len, flags)
	SOCKET theUDP;	
	char *buf;
	int len; 
	int flags;
{
	sockunion pb;
	struct sockaddr_in from;
	int fromlen;
	OSErr err;

	switch(theUDP->fType)
	{
	case SOCK_DGRAM:
		fromlen = sizeof(from);
		return recvfrom (theUDP, buf, len, flags, &from, &fromlen);
		/* We could check if the packet is from the right place, but 
		   it isn't clear this is required, so punt.  */
	case SOCK_STREAM:
		pb.tcppb.ioCRefNum = theUDP->fMacTCPRef;
		pb.tcppb.csCode = TCPRcv;
		pb.tcppb.csParam.receive.commandTimeoutValue = 0 /* infinity */;
		pb.tcppb.csParam.receive.rcvBuff = buf;
		pb.tcppb.csParam.receive.rcvBuffLen = len;
		pb.tcppb.tcpStream = theUDP->fStream;
		err = PBControl((ParamBlockRec *)&pb.tcppb,false);
		if (err) {
			SOCKET_SET_ERRNO (EIO);
			return SOCKET_ERROR;
		}
		return pb.tcppb.csParam.receive.rcvBuffLen;
	}
}

/* Send a packet to a UDP peer.  */
int
send (theUDP, buf, len, flags)
	SOCKET theUDP;
	const char *buf;
	const int len; 
	int flags;
{
	OSErr		err;
	sockunion	pb;
	wdsEntry	wds[2];

	switch(theUDP->fType)
	{
	case SOCK_DGRAM:
		return sendto (theUDP, buf, len, flags,
			       &theUDP->connect_addr, sizeof(theUDP->connect_addr));

	case SOCK_STREAM:
		wds[0].length	= len;
		wds[0].ptr		= (char *) buf;
		wds[1].length	= 0;
		pb.tcppb.ioCRefNum = theUDP->fMacTCPRef;
		pb.tcppb.csCode = TCPSend;
		pb.tcppb.csParam.send.validityFlags = timeoutValue | timeoutAction;
		pb.tcppb.csParam.send.ulpTimeoutValue = 60 /* seconds */;
		pb.tcppb.csParam.send.ulpTimeoutAction = 1 /* 1:abort 0:report */;
		pb.tcppb.csParam.send.pushFlag = true;
		pb.tcppb.csParam.send.urgentFlag = false;
		pb.tcppb.csParam.send.wdsPtr = (Ptr) wds;
		pb.tcppb.tcpStream = theUDP->fStream;
		err = PBControl((ParamBlockRec *)&pb.tcppb,false);
		if (err) {
			SOCKET_SET_ERRNO (EIO);
			return SOCKET_ERROR;
		}
		return len;
	}
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
static struct in_addr		ourAddr;
	
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
	/* take off a period from the end of the connonical host name */
	{
	int hostnamelen = strlen(host.cname);
		if (host.cname[hostnamelen-1] == '.')
			host.cname[hostnamelen-1] = 0;
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

/* Return a hostent filled in with my own IP address(es).   The rest of
   the hostent is probably not useful.  */

struct hostent *
getmyipaddr ()
{
	SOCKET sock;
	struct GetAddrParamBlock pb;
	int err;
	
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET)
		return 0;
	pb.ioCRefNum	= sock->fMacTCPRef;
	pb.csCode		= ipctlGetAddr;
	err = PBControl( (ParamBlockRec *) &pb, false );
	if (err) {
		closesocket (sock);
		SOCKET_SET_ERRNO (EIO);
		return 0;
	}
	ourAddr.s_addr = pb.ourAddress;

	/* Build result in hostent structure, which we will return to caller. */
	
	result.h_name = 0;
	result.h_aliases = 0;		/* We don't know about aliases.  */
	result.h_addrtype = AF_INET;
	result.h_length = sizeof (host.addr[0]);  /* Length of each address */
	result.h_addr_list = ipaddr_ptrs;
	ipaddr_ptrs[0] = (char*) ourAddr.s_addr;
	ipaddr_ptrs[1] = 0;

	closesocket (sock);

	return &result;
}


#define MACHOSTNAME "unknownmac"

int
gethostname(char *name, int namelen)
{
short int					refnum;
int							err;
ip_addr						ipaddr;
struct hostent				*hp;
struct GetAddrParamBlock	pb;

/* get my ip address from mactcp */
	err = OpenDriver( "\p.IPP", &refnum );
	pb.ioCRefNum	= refnum;
	pb.csCode		= ipctlGetAddr;
	err = PBControl( (ParamBlockRec *) &pb, false );
	if (err) {
		SOCKET_SET_ERRNO (EIO);
		return 0;
	}
/*jfm we never close this driver */

/* from that address find my name by asking the nameserver to resolve
 * the name from an address
 */
	ipaddr = pb.ourAddress;
	hp = gethostbyaddr((char*) &ipaddr, sizeof(ip_addr), AF_INET);
	if( hp == NULL)  
		strcpy( name, MACHOSTNAME);				/* give the default name */
	else
	{
		strncpy( name, hp->h_name, namelen);	/* use the name given */
		name[namelen-1] = 0;					/* terminate the string just in case */
	}

	return 0;
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
	if (sock == INVALID_SOCKET)
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

int
getsockname(s, name, namelen)
	SOCKET s;
	struct sockaddr_in *name;
	int *namelen;
{

	if (s == NULL)
		return(EINVAL);

	if (*namelen < sizeof(struct sockaddr_in))
		return(EINVAL);

	*namelen = sizeof(struct sockaddr_in);
	*name = s->connect_addr;

	return(0);
}

#endif /* HAVE_MACSOCK_H */
