/*
 * winccld.h -- the dynamic loaded version of the ccache DLL
 */


#ifndef KRB5_WINCCLD_H_
#define KRB5_WINCCLD_H_

#include "cacheapi.h"

typedef cc_int32 (*FP_cc_initialize)(apiCB**, const cc_int32, 
			cc_int32*, const char**);     
typedef cc_int32 (*FP_cc_shutdown)(apiCB**);            
typedef cc_int32 (*FP_cc_get_change_time)(apiCB*, cc_time_t*);    
typedef cc_int32 (*FP_cc_create)(apiCB*, const char*, const char*,
			const enum cc_cred_vers, const cc_int32, ccache_p**);
typedef cc_int32 (*FP_cc_open)(apiCB*, const char*, const enum cc_cred_vers,
			const cc_int32, ccache_p**);
typedef cc_int32 (*FP_cc_close)(apiCB*, ccache_p**);
typedef cc_int32 (*FP_cc_destroy)(apiCB*, ccache_p**);
typedef cc_int32 (*FP_cc_seq_fetch_NCs)(apiCB*, ccache_p**, ccache_cit**);
typedef cc_int32 (*FP_cc_get_NC_info)(apiCB*, struct _infoNC***);
typedef cc_int32 (*FP_cc_free_NC_info)(apiCB*, struct _infoNC***);
typedef cc_int32 (*FP_cc_get_name)(apiCB*, const ccache_p*, char**);
typedef cc_int32 (*FP_cc_set_principal)(apiCB*, const ccache_p*,
			const enum cc_cred_vers, const char*);
typedef cc_int32 (*FP_cc_get_principal)(apiCB*, ccache_p*, char**);
typedef cc_int32 (*FP_cc_set_instance)(apiCB*, const char*);
typedef cc_int32 (*FP_cc_get_instance)(apiCB*, char**);
typedef cc_int32 (*FP_cc_get_cred_version)(apiCB*, const ccache_p*,
			enum cc_cred_vers*);
typedef cc_int32 (*FP_cc_lock_request)(apiCB*, const ccache_p*,
			const cc_int32);
typedef cc_int32 (*FP_cc_store)(apiCB*, const ccache_p*, const cred_union);
typedef cc_int32 (*FP_cc_remove_cred)(apiCB*, const ccache_p*,
			const cred_union);
typedef cc_int32 (*FP_cc_seq_fetch_creds)(apiCB*, const ccache_p*, 
			cred_union**, ccache_cit**);
typedef cc_int32 (*FP_cc_free_principal)(apiCB*, char**);
typedef cc_int32 (*FP_cc_free_instance)(apiCB*, char**);
typedef cc_int32 (*FP_cc_free_name)(apiCB*, char** name);
typedef cc_int32 (*FP_cc_free_creds)(apiCB*, cred_union** pCred);

#ifdef KRB5_WINCCLD_C_
typedef struct _FUNC_INFO {
    void** func_ptr_var;
    char* func_name;
} FUNC_INFO;

#define DECL_FUNC_PTR(x) FP_##x p##x
#define MAKE_FUNC_INFO(x) { (void**) &p##x, #x }
#define END_FUNC_INFO { 0, 0 }
#else
#define DECL_FUNC_PTR(x) extern FP_##x p##x
#endif

DECL_FUNC_PTR(cc_initialize);
DECL_FUNC_PTR(cc_shutdown);
DECL_FUNC_PTR(cc_get_change_time);
DECL_FUNC_PTR(cc_create);
DECL_FUNC_PTR(cc_open);
DECL_FUNC_PTR(cc_close);
DECL_FUNC_PTR(cc_destroy);
DECL_FUNC_PTR(cc_seq_fetch_NCs);
DECL_FUNC_PTR(cc_get_NC_info);
DECL_FUNC_PTR(cc_free_NC_info);
DECL_FUNC_PTR(cc_get_name);
DECL_FUNC_PTR(cc_set_principal);
DECL_FUNC_PTR(cc_get_principal);
DECL_FUNC_PTR(cc_set_instance);
DECL_FUNC_PTR(cc_get_instance);
DECL_FUNC_PTR(cc_get_cred_version);
DECL_FUNC_PTR(cc_lock_request);
DECL_FUNC_PTR(cc_store);
DECL_FUNC_PTR(cc_remove_cred);
DECL_FUNC_PTR(cc_seq_fetch_creds);
DECL_FUNC_PTR(cc_free_principal);
DECL_FUNC_PTR(cc_free_instance);
DECL_FUNC_PTR(cc_free_name);
DECL_FUNC_PTR(cc_free_creds);

#ifdef KRB5_WINCCLD_C_
FUNC_INFO krbcc_fi[] = {
    MAKE_FUNC_INFO(cc_initialize),
    MAKE_FUNC_INFO(cc_shutdown),
    MAKE_FUNC_INFO(cc_get_change_time),
    MAKE_FUNC_INFO(cc_create),
    MAKE_FUNC_INFO(cc_open),
    MAKE_FUNC_INFO(cc_close),
    MAKE_FUNC_INFO(cc_destroy),
    MAKE_FUNC_INFO(cc_seq_fetch_NCs),
    MAKE_FUNC_INFO(cc_get_NC_info),
    MAKE_FUNC_INFO(cc_free_NC_info),
    MAKE_FUNC_INFO(cc_get_name),
    MAKE_FUNC_INFO(cc_set_principal),
    MAKE_FUNC_INFO(cc_get_principal),
    MAKE_FUNC_INFO(cc_set_instance),
    MAKE_FUNC_INFO(cc_get_instance),
    MAKE_FUNC_INFO(cc_get_cred_version),
    MAKE_FUNC_INFO(cc_lock_request),
    MAKE_FUNC_INFO(cc_store),
    MAKE_FUNC_INFO(cc_remove_cred),
    MAKE_FUNC_INFO(cc_seq_fetch_creds),
    MAKE_FUNC_INFO(cc_free_principal),
    MAKE_FUNC_INFO(cc_free_instance),
    MAKE_FUNC_INFO(cc_free_name),
    MAKE_FUNC_INFO(cc_free_creds),
    END_FUNC_INFO
};
#undef MAKE_FUNC_INFO
#undef END_FUNC_INFO
#else

#define cc_initialize pcc_initialize
#define cc_shutdown pcc_shutdown
#define cc_get_change_time pcc_get_change_time
#define cc_create pcc_create
#define cc_open pcc_open
#define cc_close pcc_close
#define cc_destroy pcc_destroy
#define cc_seq_fetch_NCs pcc_seq_fetch_NCs
#define cc_get_NC_info pcc_get_NC_info
#define cc_free_NC_info pcc_free_NC_info
#define cc_get_name pcc_get_name
#define cc_set_principal pcc_set_principal
#define cc_get_principal pcc_get_principal
#define cc_set_instance pcc_set_instance
#define cc_get_instance pcc_get_instance
#define cc_get_cred_version pcc_get_cred_version
#define cc_lock_request pcc_lock_request
#define cc_store pcc_store
#define cc_remove_cred pcc_remove_cred
#define cc_seq_fetch_creds pcc_seq_fetch_creds
#define cc_free_principal pcc_free_principal
#define cc_free_instance pcc_free_instance
#define cc_free_name pcc_free_name
#define cc_free_creds pcc_free_creds
#endif

#undef DECL_FUNC_PTR

#endif /* KRB5_WINCCLD_H_ */
