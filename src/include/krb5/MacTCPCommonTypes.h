/* 
	MacTCPCommonTypes.h  
	C type definitions used throughout MacTCP.
						
    Copyright Apple Computer, Inc. 1988-91 
    All rights reserved
	
*/

#ifndef __MACTCPCOMMONTYPES__
#define __MACTCPCOMMONTYPES__

#ifndef __TYPES__
#include <Types.h>
#endif /* __TYPES__ */

/* MacTCP return Codes in the range -23000 through -23049 */
#define inProgress				1				/* I/O in progress */

#define ipBadLapErr				-23000			/* bad network configuration */
#define ipBadCnfgErr			-23001			/* bad IP configuration error */
#define ipNoCnfgErr				-23002			/* missing IP or LAP configuration error */
#define ipLoadErr				-23003			/* error in MacTCP load */
#define ipBadAddr				-23004			/* error in getting address */
#define connectionClosing		-23005			/* connection is closing */
#define invalidLength			-23006
#define connectionExists		-23007			/* request conflicts with existing connection */
#define connectionDoesntExist	-23008			/* connection does not exist */
#define insufficientResources	-23009			/* insufficient resources to perform request */
#define invalidStreamPtr		-23010
#define streamAlreadyOpen		-23011
#define connectionTerminated	-23012
#define invalidBufPtr			-23013
#define invalidRDS				-23014
#define invalidWDS				-23014
#define openFailed				-23015
#define commandTimeout			-23016
#define duplicateSocket			-23017

/* Error codes from internal IP functions */
#define ipDontFragErr			-23032			/* Packet too large to send w/o fragmenting */
#define ipDestDeadErr			-23033			/* destination not responding */
#define icmpEchoTimeoutErr 		-23035			/* ICMP echo timed-out */
#define ipNoFragMemErr			-23036			/* no memory to send fragmented pkt */
#define ipRouteErr				-23037			/* can't route packet off-net */

#define nameSyntaxErr 			-23041		
#define cacheFault				-23042
#define noResultProc			-23043
#define noNameServer			-23044
#define authNameErr				-23045
#define noAnsErr				-23046
#define dnrErr					-23047
#define	outOfMemory				-23048

#define BYTES_16WORD   			2				/* bytes per 16 bit ip word */
#define BYTES_32WORD    		4				/* bytes per 32 bit ip word */
#define BYTES_64WORD    		8				/* bytes per 64 bit ip word */

typedef unsigned char b_8;				/* 8-bit quantity */
typedef unsigned short b_16;			/* 16-bit quantity */
typedef unsigned long b_32;				/* 32-bit quantity */

typedef b_32 ip_addr;					/* IP address is 32-bits */

typedef struct ip_addrbytes {
	union {
		b_32 addr;
		char byte[4];
		} a;
	} ip_addrbytes;
	
typedef struct wdsEntry {
	unsigned short	length;						/* length of buffer */
	char *	ptr;						/* pointer to buffer */
	} wdsEntry;

typedef struct rdsEntry {
	unsigned short	length;						/* length of buffer */
	char *	ptr;						/* pointer to buffer */
	} rdsEntry;

typedef unsigned long BufferPtr;

typedef unsigned long StreamPtr;

typedef enum ICMPMsgType {
	netUnreach, hostUnreach, protocolUnreach, portUnreach, fragReqd,
	sourceRouteFailed, timeExceeded, parmProblem, missingOption,
	lastICMPMsgType = 32767
	} ICMPMsgType;
	
typedef b_16 ip_port;

typedef struct ICMPReport {
	StreamPtr streamPtr;
	ip_addr localHost;
	ip_port localPort;
	ip_addr remoteHost;
	ip_port remotePort;
	short reportType;
	unsigned short optionalAddlInfo;
	unsigned long optionalAddlInfoPtr;
	} ICMPReport;
	

typedef OSErr (*OSErrProcPtr)();
typedef Ptr (*PtrProcPtr)();
typedef Boolean (*BooleanProcPtr)();
typedef void (*voidProcPtr)();

#endif /* __MACTCPCOMMONTYPES__ */
