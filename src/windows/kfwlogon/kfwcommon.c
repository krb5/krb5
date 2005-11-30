/*
Copyright 2005 by the Massachusetts Institute of Technology

All rights reserved.

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of the Massachusetts
Institute of Technology (M.I.T.) not be used in advertising or publicity
pertaining to distribution of the software without specific, written
prior permission.

M.I.T. DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
M.I.T. BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

*/

#include "kfwlogon.h"
#include <winbase.h>

#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <winsock2.h>
#include <lm.h>
#include <nb30.h>

/* Function Pointer Declarations for Delayed Loading */
// CCAPI
DECL_FUNC_PTR(cc_initialize);
DECL_FUNC_PTR(cc_shutdown);
DECL_FUNC_PTR(cc_get_NC_info);
DECL_FUNC_PTR(cc_free_NC_info);

// leash functions
DECL_FUNC_PTR(Leash_get_default_lifetime);
DECL_FUNC_PTR(Leash_get_default_forwardable);
DECL_FUNC_PTR(Leash_get_default_renew_till);
DECL_FUNC_PTR(Leash_get_default_noaddresses);
DECL_FUNC_PTR(Leash_get_default_proxiable);
DECL_FUNC_PTR(Leash_get_default_publicip);
DECL_FUNC_PTR(Leash_get_default_use_krb4);
DECL_FUNC_PTR(Leash_get_default_life_min);
DECL_FUNC_PTR(Leash_get_default_life_max);
DECL_FUNC_PTR(Leash_get_default_renew_min);
DECL_FUNC_PTR(Leash_get_default_renew_max);
DECL_FUNC_PTR(Leash_get_default_renewable);
DECL_FUNC_PTR(Leash_get_default_mslsa_import);

// krb5 functions
DECL_FUNC_PTR(krb5_change_password);
DECL_FUNC_PTR(krb5_get_init_creds_opt_init);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_tkt_life);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_renew_life);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_forwardable);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_proxiable);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_address_list);
DECL_FUNC_PTR(krb5_get_init_creds_password);
DECL_FUNC_PTR(krb5_build_principal_ext);
DECL_FUNC_PTR(krb5_cc_get_name);
DECL_FUNC_PTR(krb5_cc_resolve);
DECL_FUNC_PTR(krb5_cc_default);
DECL_FUNC_PTR(krb5_cc_default_name);
DECL_FUNC_PTR(krb5_cc_set_default_name);
DECL_FUNC_PTR(krb5_cc_initialize);
DECL_FUNC_PTR(krb5_cc_destroy);
DECL_FUNC_PTR(krb5_cc_close);
DECL_FUNC_PTR(krb5_cc_store_cred);
DECL_FUNC_PTR(krb5_cc_copy_creds);
DECL_FUNC_PTR(krb5_cc_retrieve_cred);
DECL_FUNC_PTR(krb5_cc_get_principal);
DECL_FUNC_PTR(krb5_cc_start_seq_get);
DECL_FUNC_PTR(krb5_cc_next_cred);
DECL_FUNC_PTR(krb5_cc_end_seq_get);
DECL_FUNC_PTR(krb5_cc_remove_cred);
DECL_FUNC_PTR(krb5_cc_set_flags);
DECL_FUNC_PTR(krb5_cc_get_type);
DECL_FUNC_PTR(krb5_free_context);
DECL_FUNC_PTR(krb5_free_cred_contents);
DECL_FUNC_PTR(krb5_free_principal);
DECL_FUNC_PTR(krb5_get_in_tkt_with_password);
DECL_FUNC_PTR(krb5_init_context);
DECL_FUNC_PTR(krb5_parse_name);
DECL_FUNC_PTR(krb5_timeofday);
DECL_FUNC_PTR(krb5_timestamp_to_sfstring);
DECL_FUNC_PTR(krb5_unparse_name);
DECL_FUNC_PTR(krb5_get_credentials);
DECL_FUNC_PTR(krb5_mk_req);
DECL_FUNC_PTR(krb5_sname_to_principal);
DECL_FUNC_PTR(krb5_get_credentials_renew);
DECL_FUNC_PTR(krb5_free_data);
DECL_FUNC_PTR(krb5_free_data_contents);
DECL_FUNC_PTR(krb5_free_unparsed_name);
DECL_FUNC_PTR(krb5_os_localaddr);
DECL_FUNC_PTR(krb5_copy_keyblock_contents);
DECL_FUNC_PTR(krb5_copy_data);
DECL_FUNC_PTR(krb5_free_creds);
DECL_FUNC_PTR(krb5_build_principal);
DECL_FUNC_PTR(krb5_get_renewed_creds);
DECL_FUNC_PTR(krb5_get_default_config_files);
DECL_FUNC_PTR(krb5_free_config_files);
DECL_FUNC_PTR(krb5_get_default_realm);
DECL_FUNC_PTR(krb5_free_default_realm);
DECL_FUNC_PTR(krb5_free_ticket);
DECL_FUNC_PTR(krb5_decode_ticket);
DECL_FUNC_PTR(krb5_get_host_realm);
DECL_FUNC_PTR(krb5_free_host_realm);
DECL_FUNC_PTR(krb5_free_addresses);
DECL_FUNC_PTR(krb5_c_random_make_octets);

// ComErr functions
DECL_FUNC_PTR(com_err);
DECL_FUNC_PTR(error_message);

// Profile functions
DECL_FUNC_PTR(profile_init);
DECL_FUNC_PTR(profile_release);
DECL_FUNC_PTR(profile_get_subsection_names);
DECL_FUNC_PTR(profile_free_list);
DECL_FUNC_PTR(profile_get_string);
DECL_FUNC_PTR(profile_release_string);

// Service functions
DECL_FUNC_PTR(OpenSCManagerA);
DECL_FUNC_PTR(OpenServiceA);
DECL_FUNC_PTR(QueryServiceStatus);
DECL_FUNC_PTR(CloseServiceHandle);
DECL_FUNC_PTR(LsaNtStatusToWinError);

// LSA Functions
DECL_FUNC_PTR(LsaConnectUntrusted);
DECL_FUNC_PTR(LsaLookupAuthenticationPackage);
DECL_FUNC_PTR(LsaCallAuthenticationPackage);
DECL_FUNC_PTR(LsaFreeReturnBuffer);
DECL_FUNC_PTR(LsaGetLogonSessionData);

// CCAPI
FUNC_INFO ccapi_fi[] = {
    MAKE_FUNC_INFO(cc_initialize),
    MAKE_FUNC_INFO(cc_shutdown),
    MAKE_FUNC_INFO(cc_get_NC_info),
    MAKE_FUNC_INFO(cc_free_NC_info),
    END_FUNC_INFO
};

FUNC_INFO leash_fi[] = {
    MAKE_FUNC_INFO(Leash_get_default_lifetime),
    MAKE_FUNC_INFO(Leash_get_default_renew_till),
    MAKE_FUNC_INFO(Leash_get_default_forwardable),
    MAKE_FUNC_INFO(Leash_get_default_noaddresses),
    MAKE_FUNC_INFO(Leash_get_default_proxiable),
    MAKE_FUNC_INFO(Leash_get_default_publicip),
    MAKE_FUNC_INFO(Leash_get_default_use_krb4),
    MAKE_FUNC_INFO(Leash_get_default_life_min),
    MAKE_FUNC_INFO(Leash_get_default_life_max),
    MAKE_FUNC_INFO(Leash_get_default_renew_min),
    MAKE_FUNC_INFO(Leash_get_default_renew_max),
    MAKE_FUNC_INFO(Leash_get_default_renewable),
    END_FUNC_INFO
};

FUNC_INFO leash_opt_fi[] = {
    MAKE_FUNC_INFO(Leash_get_default_mslsa_import),
    END_FUNC_INFO
};

FUNC_INFO k5_fi[] = {
    MAKE_FUNC_INFO(krb5_change_password),
    MAKE_FUNC_INFO(krb5_get_init_creds_opt_init),
    MAKE_FUNC_INFO(krb5_get_init_creds_opt_set_tkt_life),
    MAKE_FUNC_INFO(krb5_get_init_creds_opt_set_renew_life),
    MAKE_FUNC_INFO(krb5_get_init_creds_opt_set_forwardable),
    MAKE_FUNC_INFO(krb5_get_init_creds_opt_set_proxiable),
    MAKE_FUNC_INFO(krb5_get_init_creds_opt_set_address_list),
    MAKE_FUNC_INFO(krb5_get_init_creds_password),
    MAKE_FUNC_INFO(krb5_build_principal_ext),
    MAKE_FUNC_INFO(krb5_cc_get_name),
    MAKE_FUNC_INFO(krb5_cc_resolve),
    MAKE_FUNC_INFO(krb5_cc_default),
    MAKE_FUNC_INFO(krb5_cc_default_name),
    MAKE_FUNC_INFO(krb5_cc_set_default_name),
    MAKE_FUNC_INFO(krb5_cc_initialize),
    MAKE_FUNC_INFO(krb5_cc_destroy),
    MAKE_FUNC_INFO(krb5_cc_close),
    MAKE_FUNC_INFO(krb5_cc_copy_creds),
    MAKE_FUNC_INFO(krb5_cc_store_cred),
    MAKE_FUNC_INFO(krb5_cc_retrieve_cred),
    MAKE_FUNC_INFO(krb5_cc_get_principal),
    MAKE_FUNC_INFO(krb5_cc_start_seq_get),
    MAKE_FUNC_INFO(krb5_cc_next_cred),
    MAKE_FUNC_INFO(krb5_cc_end_seq_get),
    MAKE_FUNC_INFO(krb5_cc_remove_cred),
    MAKE_FUNC_INFO(krb5_cc_set_flags),
    MAKE_FUNC_INFO(krb5_cc_get_type),
    MAKE_FUNC_INFO(krb5_free_context),
    MAKE_FUNC_INFO(krb5_free_cred_contents),
    MAKE_FUNC_INFO(krb5_free_principal),
    MAKE_FUNC_INFO(krb5_get_in_tkt_with_password),
    MAKE_FUNC_INFO(krb5_init_context),
    MAKE_FUNC_INFO(krb5_parse_name),
    MAKE_FUNC_INFO(krb5_timeofday),
    MAKE_FUNC_INFO(krb5_timestamp_to_sfstring),
    MAKE_FUNC_INFO(krb5_unparse_name),
    MAKE_FUNC_INFO(krb5_get_credentials),
    MAKE_FUNC_INFO(krb5_mk_req),
    MAKE_FUNC_INFO(krb5_sname_to_principal),
    MAKE_FUNC_INFO(krb5_get_credentials_renew),
    MAKE_FUNC_INFO(krb5_free_data),
    MAKE_FUNC_INFO(krb5_free_data_contents),
    MAKE_FUNC_INFO(krb5_free_unparsed_name),
    MAKE_FUNC_INFO(krb5_os_localaddr),
    MAKE_FUNC_INFO(krb5_copy_keyblock_contents),
    MAKE_FUNC_INFO(krb5_copy_data),
    MAKE_FUNC_INFO(krb5_free_creds),
    MAKE_FUNC_INFO(krb5_build_principal),
    MAKE_FUNC_INFO(krb5_get_renewed_creds),
    MAKE_FUNC_INFO(krb5_free_addresses),
    MAKE_FUNC_INFO(krb5_get_default_config_files),
    MAKE_FUNC_INFO(krb5_free_config_files),
    MAKE_FUNC_INFO(krb5_get_default_realm),
    MAKE_FUNC_INFO(krb5_free_default_realm),
    MAKE_FUNC_INFO(krb5_free_ticket),
    MAKE_FUNC_INFO(krb5_decode_ticket),
    MAKE_FUNC_INFO(krb5_get_host_realm),
    MAKE_FUNC_INFO(krb5_free_host_realm),
    MAKE_FUNC_INFO(krb5_free_addresses),
    MAKE_FUNC_INFO(krb5_c_random_make_octets),
    END_FUNC_INFO
};

FUNC_INFO profile_fi[] = {
        MAKE_FUNC_INFO(profile_init),
        MAKE_FUNC_INFO(profile_release),
        MAKE_FUNC_INFO(profile_get_subsection_names),
        MAKE_FUNC_INFO(profile_free_list),
        MAKE_FUNC_INFO(profile_get_string),
        MAKE_FUNC_INFO(profile_release_string),
        END_FUNC_INFO
};

FUNC_INFO ce_fi[] = {
    MAKE_FUNC_INFO(com_err),
    MAKE_FUNC_INFO(error_message),
    END_FUNC_INFO
};

FUNC_INFO service_fi[] = {
    MAKE_FUNC_INFO(OpenSCManagerA),
    MAKE_FUNC_INFO(OpenServiceA),
    MAKE_FUNC_INFO(QueryServiceStatus),
    MAKE_FUNC_INFO(CloseServiceHandle),
    MAKE_FUNC_INFO(LsaNtStatusToWinError),
    END_FUNC_INFO
};

FUNC_INFO lsa_fi[] = {
    MAKE_FUNC_INFO(LsaConnectUntrusted),
    MAKE_FUNC_INFO(LsaLookupAuthenticationPackage),
    MAKE_FUNC_INFO(LsaCallAuthenticationPackage),
    MAKE_FUNC_INFO(LsaFreeReturnBuffer),
    MAKE_FUNC_INFO(LsaGetLogonSessionData),
    END_FUNC_INFO
};

/* Static Declarations */
static int       inited = 0;
static HINSTANCE hKrb5 = 0;
static HINSTANCE hKrb524 = 0;
static HINSTANCE hSecur32 = 0;
static HINSTANCE hAdvApi32 = 0;
static HINSTANCE hComErr = 0;
static HINSTANCE hService = 0;
static HINSTANCE hProfile = 0;
static HINSTANCE hLeash = 0;
static HINSTANCE hLeashOpt = 0;
static HINSTANCE hCCAPI = 0;

static DWORD TraceOption = 0;
static HANDLE hDLL;

void DebugEvent0(char *a) 
{
    HANDLE h; char *ptbuf[1];
    
    h = RegisterEventSource(NULL, KFW_LOGON_EVENT_NAME);
    ptbuf[0] = a;
    ReportEvent(h, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (const char **)ptbuf, NULL);
    DeregisterEventSource(h);
}

#define MAXBUF_ 512
void DebugEvent(char *b,...) 
{
    HANDLE h; char *ptbuf[1],buf[MAXBUF_+1];
    va_list marker;

    h = RegisterEventSource(NULL, KFW_LOGON_EVENT_NAME);
    va_start(marker,b);
    StringCbVPrintf(buf, MAXBUF_+1,b,marker);
    buf[MAXBUF_] = '\0';
    ptbuf[0] = buf;
    ReportEvent(h, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (const char **)ptbuf, NULL);
    DeregisterEventSource(h);
    va_end(marker);
}

void
UnloadFuncs(
    FUNC_INFO fi[], 
    HINSTANCE h
    )
{
    int n;
    if (fi)
        for (n = 0; fi[n].func_ptr_var; n++)
            *(fi[n].func_ptr_var) = 0;
    if (h) FreeLibrary(h);
}

int
LoadFuncs(
    const char* dll_name, 
    FUNC_INFO fi[], 
    HINSTANCE* ph,  // [out, optional] - DLL handle
    int* pindex,    // [out, optional] - index of last func loaded (-1 if none)
    int cleanup,    // cleanup function pointers and unload on error
    int go_on,      // continue loading even if some functions cannot be loaded
    int silent      // do not pop-up a system dialog if DLL cannot be loaded
    )
{
    HINSTANCE h;
    int i, n, last_i;
    int error = 0;
    UINT em;

    if (ph) *ph = 0;
    if (pindex) *pindex = -1;

    for (n = 0; fi[n].func_ptr_var; n++)
	*(fi[n].func_ptr_var) = 0;

    if (silent)
	em = SetErrorMode(SEM_FAILCRITICALERRORS);
    h = LoadLibrary(dll_name);
    if (silent)
        SetErrorMode(em);

    if (!h)
        return 0;

    last_i = -1;
    for (i = 0; (go_on || !error) && (i < n); i++)
    {
	void* p = (void*)GetProcAddress(h, fi[i].func_name);
	if (!p)
	    error = 1;
        else
        {
            last_i = i;
	    *(fi[i].func_ptr_var) = p;
        }
    }
    if (pindex) *pindex = last_i;
    if (error && cleanup && !go_on) {
	for (i = 0; i < n; i++) {
	    *(fi[i].func_ptr_var) = 0;
	}
	FreeLibrary(h);
	return 0;
    }
    if (ph) *ph = h;
    if (error) return 0;
    return 1;
}

static HANDLE hInitMutex = NULL;
static BOOL bInit = FALSE;

/* KFW_initialize cannot be called from DllEntryPoint */
void
KFW_initialize(void)
{
    static int inited = 0;

    if ( !inited ) {
        char mutexName[MAX_PATH];
        HANDLE hMutex = NULL;

        sprintf(mutexName, "AFS KFW Init pid=%d", getpid());
        
        hMutex = CreateMutex( NULL, TRUE, mutexName );
        if ( GetLastError() == ERROR_ALREADY_EXISTS ) {
            if ( WaitForSingleObject( hMutex, INFINITE ) != WAIT_OBJECT_0 ) {
                return;
            }
        }
        if ( !inited ) {
            inited = 1;
            LoadFuncs(KRB5_DLL, k5_fi, &hKrb5, 0, 1, 0, 0);
            LoadFuncs(COMERR_DLL, ce_fi, &hComErr, 0, 0, 1, 0);
            LoadFuncs(SERVICE_DLL, service_fi, &hService, 0, 1, 0, 0);
            LoadFuncs(SECUR32_DLL, lsa_fi, &hSecur32, 0, 1, 1, 1);
            LoadFuncs(PROFILE_DLL, profile_fi, &hProfile, 0, 1, 0, 0);
            LoadFuncs(LEASH_DLL, leash_fi, &hLeash, 0, 1, 0, 0);
            LoadFuncs(CCAPI_DLL, ccapi_fi, &hCCAPI, 0, 1, 0, 0);
            LoadFuncs(LEASH_DLL, leash_opt_fi, &hLeashOpt, 0, 1, 0, 0);
        }
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
}

void
KFW_cleanup(void)
{
    if (hLeashOpt)
        FreeLibrary(hLeashOpt);
    if (hCCAPI)
        FreeLibrary(hCCAPI);
    if (hLeash)
        FreeLibrary(hLeash);
    if (hKrb524)
        FreeLibrary(hKrb524);
    if (hSecur32)
        FreeLibrary(hSecur32);
    if (hService)
        FreeLibrary(hService);
    if (hComErr)
        FreeLibrary(hComErr);
    if (hProfile)
        FreeLibrary(hProfile);
    if (hKrb5)
        FreeLibrary(hKrb5);
}


int 
KFW_is_available(void)
{
    KFW_initialize();
    if ( hKrb5 && hComErr && hService && 
#ifdef USE_MS2MIT
         hSecur32 && 
#endif /* USE_MS2MIT */
         hProfile && hLeash && hCCAPI )
        return TRUE;

    return FALSE;
}

/* Given a principal return an existing ccache or create one and return */
int
KFW_get_ccache(krb5_context alt_ctx, krb5_principal principal, krb5_ccache * cc)
{
    krb5_context ctx;
    char * pname = 0;
    char * ccname = 0;
    krb5_error_code code;

    if (!pkrb5_init_context)
        return 0;

    if ( alt_ctx ) {
        ctx = alt_ctx;
    } else {
        code = pkrb5_init_context(&ctx);
        if (code) goto cleanup;
    }

    if ( principal ) {
        code = pkrb5_unparse_name(ctx, principal, &pname);
        if (code) goto cleanup;

	ccname = (char *)malloc(strlen(pname) + 5);
	sprintf(ccname,"API:%s",pname);
        
	code = pkrb5_cc_resolve(ctx, ccname, cc);
    } else {
        code = pkrb5_cc_default(ctx, cc);
        if (code) goto cleanup;
    }

  cleanup:
    if (ccname)
        free(ccname);
    if (pname)
        pkrb5_free_unparsed_name(ctx,pname);
    if (ctx && (ctx != alt_ctx))
        pkrb5_free_context(ctx);
    return(code);
}


int
KFW_kinit( krb5_context alt_ctx,
            krb5_ccache  alt_cc,
            HWND hParent,
            char *principal_name,
            char *password,
            krb5_deltat lifetime,
            DWORD                       forwardable,
            DWORD                       proxiable,
            krb5_deltat                 renew_life,
            DWORD                       addressless,
            DWORD                       publicIP
            )
{
    krb5_error_code		        code = 0;
    krb5_context		        ctx = 0;
    krb5_ccache			        cc = 0;
    krb5_principal		        me = 0;
    char*                       name = 0;
    krb5_creds			        my_creds;
    krb5_get_init_creds_opt     options;
    krb5_address **             addrs = NULL;
    int                         i = 0, addr_count = 0;

    if (!pkrb5_init_context)
        return 0;

    pkrb5_get_init_creds_opt_init(&options);
    memset(&my_creds, 0, sizeof(my_creds));

    if (alt_ctx)
    {
        ctx = alt_ctx;
    }
    else
    {
        code = pkrb5_init_context(&ctx);
        if (code) goto cleanup;
    }

    if ( alt_cc ) {
        cc = alt_cc;
    } else {
        code = pkrb5_cc_default(ctx, &cc);  
        if (code) goto cleanup;
    }

    code = pkrb5_parse_name(ctx, principal_name, &me);
    if (code) 
	goto cleanup;

    code = pkrb5_unparse_name(ctx, me, &name);
    if (code) 
	goto cleanup;

    if (lifetime == 0)
        lifetime = pLeash_get_default_lifetime();
    lifetime *= 60;

    if (renew_life > 0)
	renew_life *= 60;

    if (lifetime)
        pkrb5_get_init_creds_opt_set_tkt_life(&options, lifetime);
	pkrb5_get_init_creds_opt_set_forwardable(&options,
                                                 forwardable ? 1 : 0);
	pkrb5_get_init_creds_opt_set_proxiable(&options,
                                               proxiable ? 1 : 0);
	pkrb5_get_init_creds_opt_set_renew_life(&options,
                                               renew_life);
    if (addressless)
        pkrb5_get_init_creds_opt_set_address_list(&options,NULL);
    else {
	if (publicIP)
        {
            // we are going to add the public IP address specified by the user
            // to the list provided by the operating system
            krb5_address ** local_addrs=NULL;
            DWORD           netIPAddr;

            pkrb5_os_localaddr(ctx, &local_addrs);
            while ( local_addrs[i++] );
            addr_count = i + 1;

            addrs = (krb5_address **) malloc((addr_count+1) * sizeof(krb5_address *));
            if ( !addrs ) {
                pkrb5_free_addresses(ctx, local_addrs);
                goto cleanup;
            }
            memset(addrs, 0, sizeof(krb5_address *) * (addr_count+1));
            i = 0;
            while ( local_addrs[i] ) {
                addrs[i] = (krb5_address *)malloc(sizeof(krb5_address));
                if (addrs[i] == NULL) {
                    pkrb5_free_addresses(ctx, local_addrs);
                    goto cleanup;
                }

                addrs[i]->magic = local_addrs[i]->magic;
                addrs[i]->addrtype = local_addrs[i]->addrtype;
                addrs[i]->length = local_addrs[i]->length;
                addrs[i]->contents = (unsigned char *)malloc(addrs[i]->length);
                if (!addrs[i]->contents) {
                    pkrb5_free_addresses(ctx, local_addrs);
                    goto cleanup;
                }

                memcpy(addrs[i]->contents,local_addrs[i]->contents,
                        local_addrs[i]->length);        /* safe */
                i++;
            }
            pkrb5_free_addresses(ctx, local_addrs);

            addrs[i] = (krb5_address *)malloc(sizeof(krb5_address));
            if (addrs[i] == NULL)
                goto cleanup;

            addrs[i]->magic = KV5M_ADDRESS;
            addrs[i]->addrtype = AF_INET;
            addrs[i]->length = 4;
            addrs[i]->contents = (unsigned char *)malloc(addrs[i]->length);
            if (!addrs[i]->contents)
                goto cleanup;

            netIPAddr = htonl(publicIP);
            memcpy(addrs[i]->contents,&netIPAddr,4);
        
            pkrb5_get_init_creds_opt_set_address_list(&options,addrs);

        }
    }

    code = pkrb5_get_init_creds_password(ctx, 
                                       &my_creds, 
                                       me,
                                       password, // password
                                       NULL,     // no prompter
                                       hParent, // prompter data
                                       0, // start time
                                       0, // service name
                                       &options);
    if (code) 
	goto cleanup;

    code = pkrb5_cc_initialize(ctx, cc, me);
    if (code) 
	goto cleanup;

    code = pkrb5_cc_store_cred(ctx, cc, &my_creds);
    if (code) 
	goto cleanup;

 cleanup:
    if ( addrs ) {
        for ( i=0;i<addr_count;i++ ) {
            if ( addrs[i] ) {
                if ( addrs[i]->contents )
                    free(addrs[i]->contents);
                free(addrs[i]);
            }
        }
    }
    if (my_creds.client == me)
	my_creds.client = 0;
    pkrb5_free_cred_contents(ctx, &my_creds);
    if (name)
        pkrb5_free_unparsed_name(ctx, name);
    if (me)
        pkrb5_free_principal(ctx, me);
    if (cc && (cc != alt_cc))
        pkrb5_cc_close(ctx, cc);
    if (ctx && (ctx != alt_ctx))
        pkrb5_free_context(ctx);
    return(code);
}


int
KFW_get_cred( char * username, 
	      char * password,
	      int lifetime,
	      char ** reasonP )
{
    krb5_context ctx = 0;
    krb5_ccache cc = 0;
    char * realm = 0, * userrealm = 0;
    int free_realm = 0;
    krb5_principal principal = 0;
    char * pname = 0;
    krb5_error_code code;

    if (!pkrb5_init_context)
        return 0;

    if ( IsDebuggerPresent() ) {
        OutputDebugString("KFW_get_cred for token ");
        OutputDebugString(username);
        OutputDebugString("\n");
    }

    code = pkrb5_init_context(&ctx);
    if ( code ) goto cleanup;

    code = pkrb5_get_default_realm(ctx, &realm);

    userrealm = strchr(username,'@');
    if (realm) {
	free_realm = 1;
        pname = malloc(strlen(username) + strlen(realm) + 2);
        userrealm = strchr(pname, '@');
        userrealm++;
	strcat(userrealm, realm);
    } else {
        pname = strdup(username);
        userrealm = strchr(pname, '@');
        userrealm++;
	realm = userrealm;
    }
    
    if ( IsDebuggerPresent() ) {
        OutputDebugString("Realm: ");
        OutputDebugString(realm);
        OutputDebugString("\n");
    }

    code = pkrb5_parse_name(ctx, pname, &principal);
    if ( code ) goto cleanup;

    code = KFW_get_ccache(ctx, principal, &cc);
    if ( code ) goto cleanup;

    if ( lifetime == 0 )
        lifetime = pLeash_get_default_lifetime();

    if ( password && password[0] ) {
        code = KFW_kinit( ctx, cc, HWND_DESKTOP, 
                          pname, 
                          password,
                          lifetime,
                          pLeash_get_default_forwardable(),
                          pLeash_get_default_proxiable(),
                          pLeash_get_default_renewable() ? pLeash_get_default_renew_till() : 0,
                          pLeash_get_default_noaddresses(),
                          pLeash_get_default_publicip());
        if ( IsDebuggerPresent() ) {
            char message[256];
            sprintf(message,"KFW_kinit() returns: %d\n",code);
            OutputDebugString(message);
        }
        if ( code ) goto cleanup;
    }

  cleanup:
    if ( pname )
        free(pname);
    if ( cc )
        pkrb5_cc_close(ctx, cc);

    if ( code && reasonP ) {
        *reasonP = (char *)perror_message(code);
    }
    return(code);
}

void
KFW_copy_cache_to_system_file(char * user, char * szLogonId)
{
    char filename[256];
    DWORD count;
    char cachename[264] = "FILE:";
    krb5_context		ctx = 0;
    krb5_error_code		code;
    krb5_principal              princ = 0;
    krb5_ccache			cc  = 0;
    krb5_ccache                 ncc = 0;

    if (!pkrb5_init_context)
        return;

    count = GetEnvironmentVariable("TEMP", filename, sizeof(filename));
    if ( count > sizeof(filename) || count == 0 ) {
        GetWindowsDirectory(filename, sizeof(filename));
    }

    if ( strlen(filename) + strlen(szLogonId) + 2 > sizeof(filename) )
        return;

    strcat(filename, "\\");
    strcat(filename, szLogonId);    

    strcat(cachename, filename);

    DeleteFile(filename);

    code = pkrb5_init_context(&ctx);
    if (code) ctx = 0;

    code = pkrb5_parse_name(ctx, user, &princ);
    if (code) goto cleanup;

    code = KFW_get_ccache(ctx, princ, &cc);
    if (code) goto cleanup;

    code = pkrb5_cc_resolve(ctx, cachename, &ncc);
    if (code) goto cleanup;

    code = pkrb5_cc_initialize(ctx, ncc, princ);
    if (code) goto cleanup;

    code = pkrb5_cc_copy_creds(ctx,cc,ncc);

  cleanup:
    if ( cc ) {
        pkrb5_cc_close(ctx, cc);
        cc = 0;
    }
    if ( ncc ) {
        pkrb5_cc_close(ctx, ncc);
        ncc = 0;
    }
    if ( princ ) {
        pkrb5_free_principal(ctx, princ);
        princ = 0;
    }

    if (ctx)
        pkrb5_free_context(ctx);
}

int
KFW_copy_system_file_to_default_cache(char * filename)
{
    char cachename[264] = "FILE:";
    krb5_context		ctx = 0;
    krb5_error_code		code;
    krb5_principal              princ = 0;
    krb5_ccache			cc  = 0;
    krb5_ccache                 ncc = 0;
    int retval = 1;

    if (!pkrb5_init_context)
        return 1;

    if ( strlen(filename) + 6 > sizeof(cachename) )
        return 1;

    strcat(cachename, filename);

    code = pkrb5_init_context(&ctx);
    if (code) ctx = 0;

    code = pkrb5_cc_resolve(ctx, cachename, &cc);
    if (code) goto cleanup;
    
    code = pkrb5_cc_get_principal(ctx, cc, &princ);
    if (code) goto cleanup;

    code = pkrb5_cc_default(ctx, &ncc);
    if (!code) {
        code = pkrb5_cc_initialize(ctx, ncc, princ);

        if (!code)
            code = pkrb5_cc_copy_creds(ctx,cc,ncc);
    }
    if ( ncc ) {
        pkrb5_cc_close(ctx, ncc);
        ncc = 0;
    }

    retval=0;   /* success */

  cleanup:
    if ( cc ) {
        pkrb5_cc_close(ctx, cc);
        cc = 0;
    }

    DeleteFile(filename);

    if ( princ ) {
        pkrb5_free_principal(ctx, princ);
        princ = 0;
    }

    if (ctx)
        pkrb5_free_context(ctx);

    return 0;
}


int 
KFW_destroy_tickets_for_principal(char * user)
{
    krb5_context		ctx = 0;
    krb5_error_code		code;
    krb5_principal      princ = 0;
    krb5_ccache			cc  = 0;

    if (!pkrb5_init_context)
        return 0;

    if ( IsDebuggerPresent() ) {
        OutputDebugString("KFW_destroy_tickets_for_user: ");
        OutputDebugString(user);
        OutputDebugString("\n");
    }

    code = pkrb5_init_context(&ctx);
    if (code) ctx = 0;

    code = pkrb5_parse_name(ctx, user, &princ);
    if (code) goto loop_cleanup;

    code = KFW_get_ccache(ctx, princ, &cc);
    if (code) goto loop_cleanup;

    code = pkrb5_cc_destroy(ctx, cc);
    if (!code) cc = 0;

  loop_cleanup:
    if ( cc ) {
        pkrb5_cc_close(ctx, cc);
        cc = 0;
    }
    if ( princ ) {
        pkrb5_free_principal(ctx, princ);
        princ = 0;
    }

    pkrb5_free_context(ctx);
    return 0;
}

