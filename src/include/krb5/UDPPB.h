/* 
	UDPPB.h	
	C definitions of parameter block entries needed for UDP calls

    Copyright Apple Computer, Inc. 1988-89 
    All rights reserved
		
*/

#define UDPCreate		20
#define UDPRead			21
#define UDPBfrReturn	22
#define UDPWrite		23
#define UDPRelease		24
#define UDPMaxMTUSize	25
#define UDPCtlMax		29

typedef enum UDPEventCode {
	UDPDataArrival = 1,
	UDPICMPReceived,
	lastUDPEvent = 65535
	};

typedef pascal void (*UDPNotifyProc) (
		StreamPtr udpStream, 
		unsigned short eventCode, 
		Ptr userDataPtr,
		struct ICMPReport *icmpMsg);

typedef void (*UDPIOCompletionProc) (struct UDPiopb *iopb);

typedef	unsigned short	udp_port;

typedef struct UDPCreatePB {			/* for create and release calls */
	Ptr 			rcvBuff;
	unsigned long	rcvBuffLen;
	UDPNotifyProc	notifyProc;
	unsigned short	localPort;
	Ptr				userDataPtr;
} UDPCreatePB;
	
typedef struct UDPSendPB {
	unsigned short	reserved;
	ip_addr			remoteHost;
	udp_port		remotePort;
	Ptr				wdsPtr;
	Boolean			checkSum;	
	unsigned short	sendLength;
	Ptr				userDataPtr;
} UDPSendPB;
	
typedef struct UDPReceivePB {		/* for receive and buffer return calls */
	unsigned short	timeOut;
	ip_addr			remoteHost;
	udp_port		remotePort;
	Ptr 			rcvBuff;
	unsigned short	rcvBuffLen;
	unsigned short	secondTimeStamp;
	Ptr		 		userDataPtr;
} UDPReceivePB;

typedef struct UDPMTUPB {
	unsigned short 	mtuSize;
	ip_addr			remoteHost;
	Ptr				userDataPtr;
} UDPMTUPB;

typedef struct UDPiopb {
	char 				fill12[12];
	UDPIOCompletionProc	ioCompletion;
	short 				ioResult;
	char 				*ioNamePtr;		
	short 				ioVRefNum;		
	short				ioCRefNum;			
	short 				csCode;
	StreamPtr		 	udpStream;				
	union {
		struct UDPCreatePB	create;
		struct UDPSendPB	send;
		struct UDPReceivePB	receive;
		struct UDPMTUPB		mtu;
	} csParam;
} UDPiopb;
	
