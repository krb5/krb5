/*
 * Declarations for Credentials Cache API Library
 *
 * API specification: <http://web.mit.edu/pismere/kerberos/ccache-api-v2-draft.html>
 *
 *	Revision 1: Frank Dabek, 6/4/1998
 *	Revision 2: meeroh, 2/24/1999
 *
 * $Header$
 */
 
#ifndef __CCache_h__
#define __CCache_h__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <ConditionalMacros.h>

#if PRAGMA_IMPORT
#	pragma import on
#endif

/* This stuff is to make sure that we always use the same compiler options for
   this header file. Otherwise we get really exciting failure modes -- meeroh */
#if PRAGMA_STRUCT_ALIGN
	#pragma options align=mac68k
#elif PRAGMA_STRUCT_PACKPUSH
	#pragma pack(push, 2)
#elif PRAGMA_STRUCT_PACK
	#pragma pack(2)
#endif

#if PRAGMA_ENUM_ALWAYSINT
	#pragma enumsalwaysint on
#endif

#if TARGET_CPU_68K
	#pragma fourbyteints on
#endif 

#include <Processes.h>

/*
 * Constants
 */
 
/* Error codes */

enum {
	CC_NOERROR				= 0,
	CC_BADNAME				= 1,
	CC_NOTFOUND				= 2,
	CC_END					= 3,
	CC_IO					= 4,
	CC_WRITE				= 5,
	CC_NOMEM				= 6,
	CC_FORMAT				= 7,
	CC_LOCKED				= 8,
	CC_BAD_API_VERSION		= 9,
	CC_NO_EXIST				= 10,
	CC_NOT_SUPP				= 11,
	CC_BAD_PARM				= 12,
	CC_ERR_CACHE_ATTACH		= 13,
	CC_ERR_CACHE_RELEASE	= 14,
	CC_ERR_CACHE_FULL 		= 15,
	CC_ERR_CRED_VERSION		= 16
};

/* Kerberos v4 key types */

enum StringToKey_Type {
	STK_AFS = 0,
	STK_DES = 1
};

/* Credential version types */

enum {  
    CC_CRED_VUNKNOWN		= 0,
    CC_CRED_V4				= 1,
    CC_CRED_V5				= 2,
    CC_CRED_VMAX			= 3
};

/* API versions */

enum {
	CC_API_VER_1	= 1,
	CC_API_VER_2	= 2
};

/*
 * Types
 */
 
/* Basic integer types */

typedef		SInt32					cc_int32;
typedef		UInt32					cc_uint32;

/* Other simple types */

typedef		cc_int32				cc_time_t;
typedef		cc_int32				cc_nc_flags;

typedef		cc_int32				cc_result;
typedef		cc_int32				cc_api_version;
typedef		cc_int32				cc_cred_vers;
typedef		cc_uint32				cc_flags;

/* Credential structures */

/* V4 credentials */
enum {  
	MAX_V4_CRED_LEN = 1250, 
	KRB_PRINCIPAL_SZ = 40, 
	KRB_INSTANCE_SZ = 40,
	KRB_REALM_SZ = 40,
	KRB_SERVICE_SZ = 40,
	ADDR_SZ = 16 
};

typedef struct _V4credential {
	unsigned char	kversion;								/* Always 4 */
    char			principal[KRB_PRINCIPAL_SZ];			/* Principal name */
    char			principal_instance[KRB_INSTANCE_SZ];	/* Principal instance */
    char			service[KRB_SERVICE_SZ];				/* Service name */
    char			service_instance[KRB_INSTANCE_SZ];		/* Service instance */
    char			realm[KRB_REALM_SZ];					/* Realm */
    unsigned char	session_key[8];							/* Session key */
    cc_int32		kvno;									/* Key version number */
    cc_int32		str_to_key;								/* Key password hash type */
    long			issue_date;  							/* Ticket issue date */
    cc_int32		lifetime;          						/* Ticket lifetime */
    cc_uint32		address;								/* IP address of local host */
    cc_int32		ticket_sz;								/* Ticket size */
    unsigned char	ticket[MAX_V4_CRED_LEN];				/* Ticket date */
    unsigned long	oops;									/* unused. ignore */
} V4Cred_type;

/* V5 credentials */
typedef struct _cc_data {
	cc_uint32		type;
	cc_uint32		length;
	unsigned char*	data;
} cc_data;

typedef struct _cc_creds {
	char*		client;
	char*		server;
	cc_data		keyblock;
	cc_time_t	authtime;
	cc_time_t	starttime;
	cc_time_t	endtime;
	cc_time_t	renew_till;
	cc_uint32	is_skey;
	cc_uint32	ticket_flags;
	cc_data     **addresses;
	cc_data		ticket;
	cc_data		second_ticket;
	cc_data     **authdata;
} cc_creds;

/* union of v4 and v5 pointers */
typedef union cred_ptr_union_type {
    V4Cred_type* pV4Cred;
    cc_creds*    pV5Cred;
} cred_ptr_union;

/* common credentials structure */
typedef struct cred_union_type {
    cc_cred_vers cred_type;
    cred_ptr_union cred;
} cred_union;

/* Cache info structures */
typedef struct _infoNC  {
	char*			name;
	char*			principal;
	cc_cred_vers	vers;
} infoNC;

/* Opaque API references */
 
struct ccache_p;
typedef struct ccache_p ccache_p;

struct apiCB;
typedef struct apiCB apiCB;

struct ccache_cit;
typedef struct ccache_cit ccache_cit;

/*
 * Functions
 */
 
/* Initialization / termination */

cc_result
cc_initialize (
		apiCB**				cc_ctx,
		cc_api_version		api_version,
		cc_api_version*		api_supported,
		char**				vendor);

cc_result
cc_shutdown (
		apiCB**				cc_ctx);
		
/* ccache access */

cc_result
cc_open (
		apiCB*				cc_ctx,
		char*				name,
		cc_cred_vers		vers,
		cc_flags			flags,
		ccache_p**			handle);

cc_result
cc_close (
		apiCB*				cc_ctx,
		ccache_p**			handle);

cc_result
cc_create (
		apiCB*				cc_ctx,
		char*				name,
		char*				principal,
		cc_cred_vers		vers,
		cc_flags			flags,
		ccache_p**			handle);

cc_result
cc_destroy (
		apiCB*				cc_ctx,
		ccache_p**			handle);
		
cc_result
cc_set_principal (
		apiCB*				cc_ctx,
		const ccache_p*		ccache_pointer,
		cc_cred_vers		vers,
		const char*			principal);

cc_result
cc_get_principal (
		apiCB*				cc_ctx,
		const ccache_p*		ccache_pointer,
		char**				principal);

cc_result
cc_get_cred_version (
		apiCB*				cc_ctx,
		const ccache_p*		ccache_pointer,
		cc_cred_vers*		vers);

cc_result
cc_get_name (
		apiCB*				cc_ctx,
		const ccache_p*		ccache_pointer,
		char**				name);

/* credentials access */

cc_result
cc_store (
		apiCB*				cc_ctx,
		const ccache_p*		ccache_pointer,
		cred_union			cred);

cc_result
cc_remove_cred (
		apiCB*				cc_ctx,
		const ccache_p*		ccache_pointer,
		cred_union			cred);

/* Iterators */

cc_result
cc_seq_fetch_NCs_begin (
		apiCB*				cc_ctx,
		ccache_cit**		itCache);

cc_result
cc_seq_fetch_NCs_next (
		apiCB*				cc_ctx,
		ccache_p**			ccache_pointer,
		ccache_cit*			itCache);

cc_result
cc_seq_fetch_NCs_end (
		apiCB*				cc_ctx,
		ccache_cit**		itCache);

cc_result
cc_seq_fetch_creds_begin (
		apiCB*				cc_ctx,
		ccache_p*			ccache_pointer,
		ccache_cit**		itCreds);

cc_result
cc_seq_fetch_creds_next (
		apiCB*				cc_ctx,
		cred_union**		creds,
		ccache_cit*			itCreds);

cc_result
cc_seq_fetch_creds_end (
		apiCB*				cc_ctx,
		ccache_cit**		itCreds);
		
/* global ccache info */

cc_result
cc_get_change_time (
		apiCB*				cc_ctx,
		cc_time_t*			time);

cc_result
cc_get_NC_info (
		apiCB*				cc_ctx,
		infoNC***			ppNCi);

/* memory recovery */

cc_result
cc_free_principal (
		apiCB*				cc_ctx,
		char**				principal);

cc_result
cc_free_name (
		apiCB*				cc_ctx,
		char**				name);

cc_result
cc_free_creds (
		apiCB*				cc_ctx,
		cred_union**		creds);

cc_result
cc_free_NC_info (
		apiCB*				cc_ctx,
		infoNC***			ppNCi);

/* Locking -- not implemented */
enum {
	CC_LOCK_UNLOCK		= 1,
	CC_LOCK_READER		= 2,
	CC_LOCK_WRITER		= 3,
	CC_LOCK_NOBLOCK		= 16
};

cc_result
cc_lock_request (
		apiCB*				cc_ctx,
		ccache_p*			ccache_pointer,
		cc_uint32			lock_type);
			   
#if PRAGMA_STRUCT_ALIGN
	#pragma options align=reset
#elif PRAGMA_STRUCT_PACKPUSH
	#pragma pack(pop)
#elif PRAGMA_STRUCT_PACK
	#pragma pack()
#endif

#if PRAGMA_ENUM_ALWAYSINT
	#pragma enumsalwaysint reset
#endif

#if TARGET_CPU_68K
	#pragma fourbyteints reset
#endif 

#if PRAGMA_IMPORT
#	pragma import reset
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CCache_h__ */
