/* 
	TCPPB.h	
	C definitions of parameter block entries needed for TCP calls

    Copyright Apple Computer, Inc. 1988-91
    All rights reserved
	
*/


/* Command codes */

#define TCPCreate			30
#define	TCPPassiveOpen		31
#define TCPActiveOpen		32
#define TCPSend				34
#define TCPNoCopyRcv		35
#define TCPRcvBfrReturn		36
#define TCPRcv				37
#define TCPClose			38
#define TCPAbort			39
#define TCPStatus			40
#define TCPExtendedStat		41
#define TCPRelease			42
#define TCPGlobalInfo		43
#define TCPCtlMax			49

typedef enum TCPEventCode {
	TCPClosing = 1,
	TCPULPTimeout,
	TCPTerminate,
	TCPDataArrival,
	TCPUrgent,
	TCPICMPReceived,
	lastEvent = 32767
} TCPEventCode;

typedef enum TCPTerminationReason {
	TCPRemoteAbort = 2,
	TCPNetworkFailure,
	TCPSecPrecMismatch,
	TCPULPTimeoutTerminate,
	TCPULPAbort,
	TCPULPClose,
	TCPServiceError,
	lastReason = 32767
} TCPTerminationReason; 

#ifdef THINK_C
typedef ProcPtr TCPNotifyProc;
#else
typedef pascal void (*TCPNotifyProc) (
		StreamPtr tcpStream,
		unsigned short eventCode,
		Ptr userDataPtr,
		unsigned short terminReason,
		struct ICMPReport *icmpMsg);
#endif

typedef void (*TCPIOCompletionProc) (struct TCPiopb *iopb);

typedef unsigned short tcp_port;

typedef unsigned char byte;

enum {					/* ValidityFlags */
	timeoutValue = 0x80,
	timeoutAction = 0x40,
	typeOfService = 0x20,
	precedence = 0x10
};

enum {					/* TOSFlags */
	lowDelay = 0x01,
	throughPut = 0x02,
	reliability = 0x04
};

typedef struct TCPCreatePB {
	Ptr 		rcvBuff;
	unsigned long rcvBuffLen;
	TCPNotifyProc 	notifyProc;
	Ptr 		userDataPtr;
}TCPCreatePB;

typedef struct TCPOpenPB {
	byte ulpTimeoutValue;
	byte ulpTimeoutAction;
	byte validityFlags;
	byte commandTimeoutValue;
	ip_addr remoteHost;
	tcp_port remotePort;
	ip_addr localHost;
	tcp_port localPort;
	byte tosFlags;
	byte precedence;
	Boolean dontFrag;
	byte timeToLive;
	byte security;
	byte optionCnt;
	byte options[40];
	Ptr userDataPtr;
}TCPOpenPB;
	
typedef struct TCPSendPB {
	byte ulpTimeoutValue;
	byte ulpTimeoutAction;
	byte validityFlags;
	Boolean pushFlag;
	Boolean urgentFlag;
	Ptr wdsPtr;
	unsigned long sendFree;
	unsigned short sendLength;
	Ptr userDataPtr;
}TCPSendPB;
	

typedef struct TCPReceivePB {		/* for receive and return rcv buff calls */
	byte commandTimeoutValue;
	byte filler;
	Boolean markFlag;
	Boolean urgentFlag;
	Ptr rcvBuff;
	unsigned short rcvBuffLen;
	Ptr rdsPtr;
	unsigned short rdsLength;
	unsigned short secondTimeStamp;
	Ptr userDataPtr;
}TCPReceivePB;
	
typedef struct TCPClosePB {
	byte ulpTimeoutValue;
	byte ulpTimeoutAction;
	byte validityFlags;
	Ptr userDataPtr;
}TCPClosePB;
	
typedef struct HistoBucket {
	unsigned short value;
	unsigned long counter;
};
	
#define NumOfHistoBuckets	7

typedef struct TCPConnectionStats {
	unsigned long dataPktsRcvd;
	unsigned long dataPktsSent;
	unsigned long dataPktsResent;
	unsigned long bytesRcvd;
	unsigned long bytesRcvdDup;
	unsigned long bytesRcvdPastWindow;
	unsigned long  bytesSent;
	unsigned long bytesResent;
	unsigned short numHistoBuckets;
	struct HistoBucket sentSizeHisto[NumOfHistoBuckets];
	unsigned short lastRTT;
	unsigned short tmrSRTT;
	unsigned short rttVariance;
	unsigned short tmrRTO;
	byte sendTries;
	byte sourchQuenchRcvd;
}TCPConnectionStats;
	
typedef struct TCPStatusPB {
	byte ulpTimeoutValue;
	byte ulpTimeoutAction;
	long unused;
	ip_addr remoteHost;
	tcp_port remotePort;
	ip_addr localHost;
	tcp_port localPort;
	byte tosFlags;
	byte precedence;
	byte connectionState;
	unsigned short sendWindow;
	unsigned short rcvWindow;
	unsigned short amtUnackedData;
	unsigned short amtUnreadData;
	Ptr securityLevelPtr;
	unsigned long sendUnacked;
	unsigned long sendNext;
	unsigned long congestionWindow;
	unsigned long rcvNext;
	unsigned long srtt;
	unsigned long lastRTT;
	unsigned long sendMaxSegSize;
	struct TCPConnectionStats *connStatPtr;
	Ptr userDataPtr;
}TCPStatusPB;
	
typedef struct TCPAbortPB {
	Ptr userDataPtr;
}TCPAbortPB;
	
typedef struct TCPParam {
	unsigned long tcpRtoA;
	unsigned long tcpRtoMin;
	unsigned long tcpRtoMax;
	unsigned long tcpMaxSegSize;
	unsigned long tcpMaxConn;
	unsigned long tcpMaxWindow;
}TCPParam;

typedef struct TCPStats {
	unsigned long tcpConnAttempts;
	unsigned long tcpConnOpened;
	unsigned long tcpConnAccepted;
	unsigned long tcpConnClosed;
	unsigned long tcpConnAborted;
	unsigned long tcpOctetsIn;
	unsigned long tcpOctetsOut;
	unsigned long tcpOctetsInDup;
	unsigned long tcpOctetsRetrans;
	unsigned long tcpInputPkts;
	unsigned long tcpOutputPkts;
	unsigned long tcpDupPkts;
	unsigned long tcpRetransPkts;
}TCPStats;
	
typedef struct TCPGlobalInfoPB {
	struct TCPParam *tcpParamPtr;
	struct TCPStats *tcpStatsPtr;
	StreamPtr *tcpCDBTable;
	Ptr userDataPtr;
	unsigned short maxTCPConnections;
}TCPGlobalInfoPB;
	
typedef struct TCPiopb {
	char 				fill12[12];
	TCPIOCompletionProc	ioCompletion;
	short 				ioResult;
	char 				*ioNamePtr;		
	short 				ioVRefNum;		
	short				ioCRefNum;			
	short 				csCode;
	StreamPtr		 	tcpStream;				
	union {
		struct TCPCreatePB create;
		struct TCPOpenPB open;
		struct TCPSendPB send;
		struct TCPReceivePB receive;
		struct TCPClosePB close;
		struct TCPAbortPB abort;
		struct TCPStatusPB status;
		struct TCPGlobalInfoPB globalInfo;
		} csParam;
}TCPiopb;
	
