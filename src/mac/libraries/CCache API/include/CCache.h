/*************************************************************
 *
 *	Header file for Credential Cache API for MacOS
 *
 *	-as defined by the document found at http://www.umich.edu/~sgr/v4Cache/
 *	-definitions borrowed from a windows implementation found at
 *	 /afs/umich.edu/user/s/g/sgr/Public/TsoCacheDll shell/
 *
 *	Revision 1: Frank Dabek, 6/4/98
 * 				added missing calls from revision four of the API
 *				deleted some WIN specific Information
 *				added some misssing definitions
 *				renamed to CCache.h
 **************************************************************/
#ifndef _CCache_h_
#define _CCache_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(__CFM68K__) && !defined(__USING_STATIC_LIBS__)
#	pragma import on
#endif

/* This stuff is to make sure that we always use the same compiler options for
   this header file. Otherwise we get really exciting failure modes -- meeroh */
#include <ConditionalMacros.h>

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
** The Official Error Codes
*/
#define	CC_NOERROR	0
#define CC_BADNAME	1
#define CC_NOTFOUND	2
#define CC_END		3
#define CC_IO		4
#define CC_WRITE	5
#define CC_NOMEM	6
#define CC_FORMAT	7
#define CC_LOCKED	8
#define CC_BAD_API_VERSION	9
#define CC_NO_EXIST	10
#define CC_NOT_SUPP	11
#define CC_BAD_PARM 12
#define CC_ERR_CACHE_ATTACH 13
#define CC_ERR_CACHE_RELEASE 14
#define CC_ERR_CACHE_FULL  15
#define CC_ERR_CRED_VERSION  16

#define CRED_TYPE_IN_UNION

typedef		SInt32		cc_int32;
typedef		UInt32		cc_uint32;
typedef		cc_int32	cc_time_t;
typedef		cc_int32	cc_nc_flags;
//typedef short cc_cred_vers;

/*
 * Enumerations and constants
 */
	
enum StringToKey_Type {
	STK_AFS = 0,
	STK_DES = 1
};

enum {  
	MAX_V4_CRED_LEN = 1250, 
	KRB_PRINCIPAL_SZ = 40, 
	KRB_INSTANCE_SZ = 40,
	KRB_REALM_SZ = 40,
	KRB_SERVICE_SZ = 40,
	ADDR_SZ = 16 
};

// version indentfiers
// extend to authentication schemes beyond Kerberos?
enum cc_cred_vers {  
    CC_CRED_VUNKNOWN = 0,       // For validation
    CC_CRED_V4 = 1,
    CC_CRED_V5 = 2,
    CC_CRED_VMAX = 3,            // For validation
    CC_INVALID_RECORD = 99
};

/*
 * Credentials structures
 */

// V4 Credentials
typedef struct _V4credential {
	unsigned char	kversion;
    char			principal[KRB_PRINCIPAL_SZ];
    char			principal_instance[KRB_INSTANCE_SZ];
    char			service[KRB_SERVICE_SZ];
    char			service_instance[KRB_INSTANCE_SZ];
    char			realm[KRB_REALM_SZ];
    unsigned char	session_key[8];
    cc_int32		kvno;
    enum StringToKey_Type	str_to_key;
    long			issue_date;  
    cc_int32		lifetime;          
    char			address[ADDR_SZ];       // IP Address of local host
    cc_int32		ticket_sz;    
    unsigned char	ticket[MAX_V4_CRED_LEN];
    unsigned long	oops;
} V4Cred_type;

// V5 credentials
typedef struct _cc_data {
	cc_int32		type; // should be one of above // FIXME: wth is this field for??
	cc_int32		length;
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
	int			is_skey;
	cc_int32	ticket_flags;
	cc_data     **addresses;
	cc_data		ticket;
	cc_data		second_ticket; //????
	cc_data     **authdata;
} cc_creds;

//union of v4, v5 pointers
typedef union cred_ptr_union_type {
    V4Cred_type* pV4Cred;
    cc_creds*    pV5Cred;
} cred_ptr_union;

//version 4 and version 5 union data type
typedef struct cred_union_type {
#ifdef CRED_TYPE_IN_UNION
    enum cc_cred_vers cred_type;
#endif
    cred_ptr_union cred;
} cred_union;

/*
 * Cache info structures
 */

typedef struct _infoNC  {
	char*			name;
	char*			principal;
	enum	cc_cred_vers	vers;
} infoNC;

/*
 * Opaque structures
 * (you never need anything but pointers)
 */
 
struct ccache_p;
typedef struct ccache_p ccache_p;

struct apiCB;
typedef struct apiCB apiCB;

struct ccache_cit;
typedef struct ccache_cit ccache_cit;

/*
** The official (externally visible) API
*/

/*
 * Note that some of the types in the API below are typedefs, to match the API spec.
 * This is because I expect at least some of them to change in the future.
 */
 
typedef		int						cc_result;
typedef		int						cc_api_version;
typedef		enum cc_cred_vers		cc_cred_vers;
typedef		int						cc_flags;

#define CC_API_VER_1	1
#define CC_API_VER_2	2

// -- Main cache routines ------

/* Initialize the Credentials Cache, return a control structure in cc_ctx,
	This should be the entry point of the shared library, or called from
	the entry point */
cc_result
cc_initialize (
		apiCB**				cc_ctx,			// < SL's primary control structure. 
											//   returned here, passed everywhere else 
		cc_api_version		api_version,	// > ver supported by caller (use CC_API_VER_1)
		cc_api_version*		api_supported,	// < if ~NULL, returned max ver supported by DLL
		char**				vendor);		// < if ~NULL, returns read only C string, vendor name */

/* Termination routine */
cc_result
cc_shutdown (
		apiCB**				cc_ctx);		// <> SL's primary control structure. NULL after call. 


/* Open a name cache within the ccache designated by name and version? 
 	Returns a control struture pointer to the NC in *handle */
cc_result
cc_open (
		apiCB*				cc_ctx,				// > SL's primary control structure
		char*				name,				// > name of pre-created cache
		cc_cred_vers		vers,				// > version of credentials held in this NC 
		cc_flags			flags,				// > options
		ccache_p**			handle);			// < named cache control structure 

/* Close and deallocate memory assoicated with the named cache pointed to by *handle */
cc_result
cc_close (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		ccache_p**			handle);			// <> named cache control structure. NULL after call. 

/* Create a new named cache in the cache cc_ctx.
Specify the cache by: a name, a principal, a version
return a pointer to the control structure for the cache via handle */
cc_result
cc_create (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		char*				name,				// > name of cache to be [destroyed if exists, then] created
		char*				principal,			// > name of principal associated with named cache
		cc_cred_vers		vers,				// > version of credentials to be held in cache
		cc_flags			flags,				// > options
		ccache_p**			handle);			// < named cache control structure 

/* Destroy cache associated with the handle (handle becomes invalid) */
cc_result
cc_destroy (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		ccache_p**			handle);			// <> named cache control structure. NULL after call.

/* Get the global last changed time variable for the CCache 
   Replace this with a change counter instead of an actual time?*/
cc_result
cc_get_change_time (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		cc_time_t*			time);				// < time of last change to named cache

// -- Named Cache routines ---------

/* store the credentials (tickets) in cred in the named cache pointed 
to by handle.  Maybe the last argument should be more general? */
cc_result
cc_store (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		const ccache_p*		ccache_pointer,		// > named cache control structure
		cred_union			cred);				// > credentials to store in cache named

/* Remove the credentials pointed to by cred from the Named Cache pointed to
by handle. */
cc_result
cc_remove_cred (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		const ccache_p*		ccache_pointer,		// > named cache control structure
		cred_union			cred);				// > credentials to remove from named cache

/* set the principal of the NC *ccache_pointer to principal,
	principal should be a null terminated C string */
cc_result
cc_set_principal (
		apiCB*				cc_ctx,				// > cs 
		const ccache_p*		ccache_pointer,		// > NC
		cc_cred_vers		vers,				// > version: to check pointer?
		const char*			principal);			// > new principal name

/* Get the name of the principal associated with the NC handle */
cc_result
cc_get_principal (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		const ccache_p*		ccache_pointer,		// > named cache control structure
		char**				principal);			// < name of principal associated with named cache
												//   Free via cc_free_principal()

/* Get version of credentials stored in the NC pointed to by ccache_pointer */ 
cc_result
cc_get_cred_version (
		apiCB*				cc_ctx,				// > cs
		const ccache_p*		ccache_pointer,		// > the named cache
		cc_cred_vers*		vers);				// <> the version of credentials in the NC

/* Return the name of the NC specified by ccache_p */
cc_result
cc_get_name (
		apiCB*				cc_ctx,				// > control struct
		const ccache_p*		ccache_pointer, 	// > NC
		char**				name);				// <> name					


//  - Search routines ----

/*
Sequentially open every NC in the CCache. 
To use (?): initially set handle and itCache to NULL
after each call set itCache to handle,
repeated calls will return all currently held NC's
*/
cc_result
cc_seq_fetch_NCs_begin (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		ccache_cit**		itCache);			// <> iterator used by DLL, set to NULL before first call

cc_result
cc_seq_fetch_NCs_next (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		ccache_p**			ccache_pointer,		// <> named cache control structure (close, then open next)
		ccache_cit*			itCache);			// <> iterator used by DLL, set to NULL before first call

cc_result
cc_seq_fetch_NCs_end (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		ccache_cit**		itCache);			// <> iterator used by DLL, set to NULL before first call

/* Sequentially fetch every set of credentials in the Named Cache handle
use similiarly to cc_seq_fetch_NCs */
cc_result
cc_seq_fetch_creds_begin (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		ccache_p*			ccache_pointer,		// > named cache control structure
		ccache_cit**		itCreds);			// <> iterator used by DLL, set to NULL before first call

cc_result
cc_seq_fetch_creds_next (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		cred_union**		creds,				// < filled in by DLL, free via cc_free_creds()
		ccache_cit*			itCreds);			// <> iterator used by DLL, set to NULL before first call

cc_result
cc_seq_fetch_creds_end (
		apiCB*				cc_ctx,				// > DLL's primary control structure
		ccache_cit**		itCreds);			// <> iterator used by DLL, set to NULL before first call

/* a wrapper for cc_seq_fetch_NCs.
	Returns: a null terminated list (array) of pointers to infoNC structs
	if this works, maybe we should hide that seq call...
	*/
cc_result
cc_get_NC_info(apiCB *cc_ctx,		// > control structure
			 infoNC*** ppNCi);		// <> info about the NC (yes.. three asterisks...)

				
// -- Memory recovery ---------

cc_result
cc_free_principal(apiCB* cc_ctx,		// > DLL's primary control structure
				  char** principal);// <> principal to be freed, returned as NULL
									//   (from cc_get_principal())
cc_result
cc_free_name(apiCB* cc_ctx,			// > DLL's primary control structure
			 char** name);			// <> name to be freed, returned as NULL
									//   (from cc_seq_fetch_cache())

/* free storage associated with cred_union** */
cc_result
cc_free_creds(apiCB* cc_ctx,			// > DLL's primary control structure
			  cred_union** creds);		// <> creds (from cc_seq_fetch_creds()) to be freed
										//    Returned as NULL.

/* Free that nasty array we created above */
cc_result
cc_free_NC_info(apiCB *cc_ctx,		// > control structure
				infoNC*** ppNCi);	// <> pointer to free
							 

// -- Locking ----------

#define CC_LOCK_UNLOCK	 1
#define CC_LOCK_READER	 2
#define CC_LOCK_WRITER	 3
#define CC_LOCK_NOBLOCK	16

/* Place a lock on the Named Cache handle, lock types are above 
NB: API indicates that this call is not implemented*/
int
cc_lock_request(apiCB* cc_ctx,		// > DLL's primary control structure
				ccache_p* ccache_pointer,		// > named cache control structure
				int lock_type);		// > one (or combination) of above defined lock types
			   
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

#if defined(__CFM68K__) && !defined(__USING_STATIC_LIBS__)
#	pragma import reset
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* Krb_CCacheAPI_h_ */
