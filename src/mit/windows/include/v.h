/* v.h -- header for vlib.c */

#ifndef _VERSION_INC
#define _VERSION_INC

/*
 * values for op_code field
 */

enum v_op_code
	{
	V_CHECK,				/* op codes from server to client */
	V_CHECK_AND_LOG,
	V_LOG,
	V_LOG_PANIC,
	V_OK,					/* op codes from client to server */
	V_ERROR,
	V_BAD_OP_CODE				/* make sure this one is last */
		};

/*
 * Values for status field
 */


#define V_REQUIRED 		'R'		/* new verison is absolutely required!! */
#define V_RECOMMENDED 		'r'		/* new version is recommended. */
#define V_OPTIONAL 		'o'		/* new version is optional */
#define V_UP_TO_DATE		'u'
#define V_NEW_DOCUMENTATION	'd'
#define V_MESSAGE		'm'		/* arbitrary message */
#define V_BAD_STATUS		'?'		/* make sure this one is last */

static struct 
	{
	char status;
	char *status_name;
	} version_status[] = 
	{
	V_REQUIRED,		"required",
	V_RECOMMENDED,		"recommended",
	V_OPTIONAL,		"optional",
	V_UP_TO_DATE,		"up_to_date",
	V_NEW_DOCUMENTATION,	"new_documentation",
	V_MESSAGE,		"message",
	V_BAD_STATUS,		"bad_status" 
		};

#define V_MAXDATA 700


/*
 * The general strategy here is we have two formats, a parsed format and a network format...
 * "v_info" is parsed, and "v_pkt" is for the network.  Note that the total size of all the 
 * strings in "v_info" had better fit into V_MAXDATA or we'll have some trouble assembling
 * the packet.  In a future protocol version, perhaps we'll actually USE the packet sequencing
 * fields we've already declared, and send things in multiple packets....
 */

struct v_info 
	{
	char *appl_name;			/* Typically, these are pointers into */
	char *appl_vers;			/* a struct v_pkt's */
	char *platform;				/* data field (and are null-terminated strings) */
	char *status;				/* status of this version */
						/* this string should be length 1, eg, V_OPTIONAL */
	char *message;
	};

struct v_pkt 
	{
	unsigned short protocol_version;
	unsigned short packet_number;
	unsigned short number_of_packets;
	unsigned short op_code;
	unsigned long  seq;
	char data[V_MAXDATA];			/* buffer of null delimited strings */
	};

#ifdef TEST
# define VERSION_FILE    "/afs/net/project/net_dev/versions/test-version.txt"
# define VERSION_DB_FILE "/afs/net/project/net_dev/versions/test-db"
#else
# define VERSION_FILE    "/afs/net/project/net_dev/version_db/version.txt"
# define VERSION_DB_FILE "/afs/net/project/net_dev/version_db/db"
#endif

#define VERSION_LOG_DIR "/site/versions/"
#define VERSION_ERROR_LOG "bad-requests"
#define VERSION_SERVER_HOST "versions.mit.edu"
#define VERSION_SERVER_PORT 8500
#define VERSION_CLIENT_PORT (VERSION_SERVER_PORT+1)
#define VERSION_PROTOCOL_VERSION 1
#define V_BASE_SIZE	(sizeof(struct v_pkt)-V_MAXDATA)
#define DLM ':'
#define KEY_SIZE   100
#define LOG_CLASS LOG_LOCAL4

#define V_MACOS "MacOS"
#endif /* _VERSION_INC */
/* end of file */
