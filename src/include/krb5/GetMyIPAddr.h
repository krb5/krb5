/* 
	GetMyIPAddr.h	
	C definitions of parameter block entries needed for IP calls

    Copyright Apple Computer, Inc. 1989 
    All rights reserved
	
*/

#ifndef __GETMYIPADDR__
#define __GETMYIPADDR__

#ifndef __MACTCPCOMMONTYPES__
#include "MacTCPCommonTypes.h"
#endif

#define ipctlGetAddr		15			/* csCode to get our IP address */

#define GetIPParamBlockHeader 	\
	struct QElem *qLink; 	\
	short qType; 			\
	short ioTrap; 			\
	Ptr ioCmdAddr; 			\
	ProcPtr ioCompletion; 	\
	OSErr ioResult; 		\
	StringPtr ioNamePtr; 	\
	short ioVRefNum;		\
	short ioCRefNum;		\
	short csCode

struct GetAddrParamBlock {
	GetIPParamBlockHeader;		/* standard I/O header */
	ip_addr	ourAddress;			/* our IP address */
	long	ourNetMask;			/* our IP net mask */
	};

#endif
