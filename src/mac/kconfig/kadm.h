/*
 * Copyright 1991-1994 by The University of Texas at Austin
 * All rights reserved.
 *
 * For infomation contact:
 * Rick Watson
 * University of Texas
 * Computation Center, COM 1
 * Austin, TX 78712
 * r.watson@utexas.edu
 * 512-471-3241
 */

#define			KRB_PROT_VERSION		4

#define ntohl(x) (x)
#define ntohs(x) (x)
#define htonl(x) (x)
#define htons(x) (x)

typedef struct pak_ {
	int len;							/* data length */
	unsigned char *data;				/* pointer to data */
	/* data goes here */
} paktype;

struct tcprequest {
	struct tcprequest *next;
	paktype *pak;
	char *tcpbuf;						/* buffer for mactcp */
	StreamPtr stream;					/* udp stream pointer */
	TCPiopb wpb;						/* pb for writes */
	TCPiopb rpb;						/* pb for reads */
	wdsEntry wds[3];					/* wds for writing */
	ip_addr remoteHost;					/* address of kerberos server */
	ip_addr localHost;
	unsigned short remotePort;			/* remote port */
	unsigned short localPort;			/* local port */
	int timeout;						/* timeout in seconds */
	int retries;						/* number of times to retry */
	short result;						/* request result */
	unsigned short xlen;				/* transmit length */
	unsigned char rbuf[750];			/* receive buffer */
	Boolean readheader;					/* true if reading 4 byte header */
	unsigned short header;				/* length header */
};
typedef struct tcprequest tcprequest;
/*
 * result values
 */
#define UR_TIMEOUT 1					/* request timed out */
#define UR_READERROR 2					/* read error */
#define UR_READDONE 3					/* read finished successfully */

/*
 * Kadm constants
 */
#define CHANGE_PW		2
#define KADM_VERSTR		"KADM0.0A"
#define KADM_VERSIZE	strlen(KADM_VERSTR)
#define KADM_ULOSE	"KYOULOSE"	/* sent back when server can't decrypt client's msg */

#define HOST_BYTE_ORDER (*(char *)&ONE)

/*
 * Errors and associated text for get ticket routines.
 * See krbe_text[].
 */
enum KRBE {
	KRBE_OK = 0,						/* no error */
	KRBE_FAIL,							/* General failure */
	KRBE_SKEW,							/* Clock Skew */
	KRBE_PROT,							/* Protocol Error */
	KRBE_PASS,							/* Invalid login or password */
	KRBE_TIMO,							/* Timeout */
	KRBE_MEM,							/* No memory */
	KRBE_N								/* must be last */
};

/* Message types , always leave lsb for byte order */

#define			AUTH_MSG_KDC_REQUEST					 1<<1
#define			AUTH_MSG_KDC_REPLY						 2<<1
#define			AUTH_MSG_APPL_REQUEST					 3<<1
#define			AUTH_MSG_APPL_REQUEST_MUTUAL			 4<<1
#define			AUTH_MSG_ERR_REPLY						 5<<1
#define			AUTH_MSG_PRIVATE						 6<<1
#define			AUTH_MSG_SAFE							 7<<1
#define			AUTH_MSG_APPL_ERR						 8<<1
#define			AUTH_MSG_DIE							63<<1


/* include space for '.' and '@' */
#define			MAX_K_NAME_SZ	(ANAME_SZ + INST_SZ + REALM_SZ + 2)
#define			KKEY_SZ			100
#define			VERSION_SZ		1
#define			MSG_TYPE_SZ		1
#define			DATE_SZ			26		/* RTI date output */
#define			MAX_KTXT_LEN	1250
#define KRB_SENDAUTH_VLEN 8			/* length for version strings */
#define K_FLAG_ORDER	0		/* bit 0 --> lsb */

/* 
 * Maximum alloable clock skew in seconds 
 */
#define			CLOCK_SKEW		5*60

#define MSBFIRST					/* macintosh 68000 */

#ifdef LSBFIRST
#define lsb_net_ulong_less(x,y) ((x < y) ? -1 : ((x > y) ? 1 : 0))
#define lsb_net_ushort_less(x,y) ((x < y) ? -1 : ((x > y) ? 1 : 0))
#else
/* MSBFIRST */
#define uchar_comp(x,y) \
        (((x)>(y))?(1):(((x)==(y))?(0):(-1)))
/* This is gross, but... */
#define lsb_net_ulong_less(x, y) long_less_than((unsigned char *)&x, (unsigned char *)&y)
#define lsb_net_ushort_less(x, y) short_less_than((unsigned char *)&x, (unsigned char *)&y)

#define long_less_than(x,y) \
        (uchar_comp((x)[3],(y)[3])?uchar_comp((x)[3],(y)[3]): \
	 (uchar_comp((x)[2],(y)[2])?uchar_comp((x)[2],(y)[2]): \
	  (uchar_comp((x)[1],(y)[1])?uchar_comp((x)[1],(y)[1]): \
	   (uchar_comp((x)[0],(y)[0])))))
#define short_less_than(x,y) \
	  (uchar_comp((x)[1],(y)[1])?uchar_comp((x)[1],(y)[1]): \
	   (uchar_comp((x)[0],(y)[0])))

#endif /* LSBFIRST */
