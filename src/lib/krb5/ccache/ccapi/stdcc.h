#include "krb5.h"
#include "k5-int.h"
	
#ifdef USE_CCAPI
#include <CredentialsCache2.h>
#endif

#if defined(_WIN32)
#include "cacheapi.h"
#endif

#define kStringLiteralLen 255

/* globals to be exported */
extern krb5_cc_ops krb5_cc_stdcc_ops;

/*
 * structure to stash in the cache's data field
 */
typedef struct _stdccCacheData {
     	char *cache_name;
	ccache_p *NamedCache;
} stdccCacheData, *stdccCacheDataPtr;


/* function protoypes  */

void krb5_stdcc_shutdown(void);

krb5_error_code KRB5_CALLCONV krb5_stdcc_close
        (krb5_context, krb5_ccache id );

krb5_error_code KRB5_CALLCONV krb5_stdcc_destroy 
        (krb5_context, krb5_ccache id );

krb5_error_code KRB5_CALLCONV krb5_stdcc_end_seq_get 
        (krb5_context, krb5_ccache id , krb5_cc_cursor *cursor );

krb5_error_code KRB5_CALLCONV krb5_stdcc_generate_new 
        (krb5_context, krb5_ccache *id );

const char * KRB5_CALLCONV krb5_stdcc_get_name 
        (krb5_context, krb5_ccache id );

krb5_error_code KRB5_CALLCONV krb5_stdcc_get_principal 
        (krb5_context, krb5_ccache id , krb5_principal *princ );

krb5_error_code KRB5_CALLCONV krb5_stdcc_initialize 
        (krb5_context, krb5_ccache id , krb5_principal princ );

krb5_error_code KRB5_CALLCONV krb5_stdcc_next_cred 
        (krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds );

krb5_error_code KRB5_CALLCONV krb5_stdcc_resolve 
        (krb5_context, krb5_ccache *id , const char *residual );
     
krb5_error_code KRB5_CALLCONV krb5_stdcc_retrieve 
        (krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds );

krb5_error_code KRB5_CALLCONV krb5_stdcc_start_seq_get 
        (krb5_context, krb5_ccache id , krb5_cc_cursor *cursor );

krb5_error_code KRB5_CALLCONV krb5_stdcc_store 
        (krb5_context, krb5_ccache id , krb5_creds *creds );

krb5_error_code KRB5_CALLCONV krb5_stdcc_set_flags 
        (krb5_context, krb5_ccache id , krb5_flags flags );

krb5_error_code KRB5_CALLCONV krb5_stdcc_remove 
        (krb5_context, krb5_ccache id , krb5_flags flags, krb5_creds *creds);
