/* 
	AddressXlation.h		
	MacTCP name to address translation routines.

    Copyright Apple Computer, Inc. 1988-91
    All rights reserved
	
*/	
#ifndef __ADDRESSXLATION__
#define __ADDRESSXLATION__

#ifndef __MACTCPCOMMONTYPES__
#include "MacTCPCommonTypes.h"
#endif

#define NUM_ALT_ADDRS	4

typedef struct hostInfo {
	long	rtnCode;
	char cname[255];
	unsigned long addr[NUM_ALT_ADDRS];
};

typedef enum AddrClasses {
	A = 1,
	NS,
	CNAME = 5,
	HINFO = 13,
	MX = 15,
	lastClass = 32767
} AddrClasses; 

typedef struct HInfoRec {
	char cpuType[30];
	char osType[30];
	};

typedef struct MXRec {
	unsigned short preference;
	char exchange[255];
	};
	
typedef struct returnRec {
	long	rtnCode;
	char cname[255];
	union {
		unsigned long addr[NUM_ALT_ADDRS];
		struct HInfoRec hinfo;
		struct MXRec mx;
	} rdata;
};

typedef struct cacheEntryRecord {
	char *cname;
	unsigned short type;
	unsigned short cacheClass;
	unsigned long ttl;
	union {
		char *name;
		ip_addr addr;
	} rdata;
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef THINK_C

	typedef ProcPtr EnumResultProcPtr;
	typedef ProcPtr ResultProcPtr;
	typedef ProcPtr ResultProc2Ptr;
	
#else

	typedef pascal void (*EnumResultProcPtr)(struct cacheEntryRecord *cacheEntryRecordPtr, char *userDataPtr);
	typedef pascal void (*ResultProcPtr)(struct hostInfo *hostInfoPtr, char *userDataPtr);
	typedef pascal void (*ResultProc2Ptr)(struct returnRec *returnRecPtr, char *userDataPtr);

#endif

extern OSErr OpenResolver(char *fileName);

extern OSErr StrToAddr(char *hostName, struct hostInfo *hostInfoPtr, ResultProcPtr ResultProc, char *userDataPtr);

extern OSErr AddrToStr(unsigned long addr, char *addrStr);

extern OSErr EnumCache(EnumResultProcPtr enumResultProc, char *userDataPtr);

extern OSErr AddrToName(ip_addr addr, struct hostInfo *hostInfoPtr, ResultProcPtr ResultProc, char *userDataPtr);

extern OSErr HInfo(char *hostName, struct returnRec *returnRecPtr, ResultProc2Ptr resultProc, char *userDataPtr);

extern OSErr MXInfo(char *hostName, struct returnRec *returnRecPtr, ResultProc2Ptr resultProc, char *userDataPtr);

extern OSErr CloseResolver(void);

#ifdef __cplusplus
}
#endif

#endif /* __ADDRESSXLATION__ */
