//#include "k5-int.h"
#include "krb5.h"
#include "CCache.h"

#define kStringLiteralLen 255

//globals to be exported
extern krb5_cc_ops krb5_cc_stdcc_ops;

//structure to stash in the cache's data field
//only holds another pointer to the actual cache right now
typedef struct _stdccCacheData {
	ccache_p *NamedCache;
} stdccCacheData, *stdccCacheDataPtr;


//function protoypes complete with bogus windowsesque macros.. 

KRB5_DLLIMP krb5_error_code  krb5_stdcc_close
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_destroy 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_end_seq_get 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_generate_new 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache *id ));

KRB5_DLLIMP char *  krb5_stdcc_get_name 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_get_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_initialize 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_next_cred 
        KRB5_PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_resolve 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache *id , const char *residual ));
     
KRB5_DLLIMP krb5_error_code  krb5_stdcc_retrieve 
        KRB5_PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_start_seq_get 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_store 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_creds *creds ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_set_flags 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_flags flags ));

KRB5_DLLIMP krb5_error_code  krb5_stdcc_remove 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_flags flags, krb5_creds *creds));