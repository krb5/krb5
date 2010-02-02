/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#ifndef __KHIMAIRA_DYNIMPORT_H
#define __KHIMAIRA_DYNIMPORT_H

/* Dynamic imports */
#include<khdefs.h>
#include<tlhelp32.h>

#if _WIN32_WINNT < 0x0501
#define KHM_SAVE_WIN32_WINNT _WIN32_WINNT
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include<ntsecapi.h>
#ifdef KHM_SAVE_WIN32_WINNT
#undef _WIN32_WINNT
#define _WIN32_WINNT KHM_SAVE_WIN32_WINNT
#undef KHM_SAVE_WIN32_WINNT
#endif

extern HINSTANCE hKrb4;
extern HINSTANCE hKrb5;
extern HINSTANCE hProfile;

///////////////////////////////////////////////////////////////////////////////

#ifdef _WIN64
#define CCAPI_DLL     "krbcc64.dll"
#define KRBCC32_DLL   "krbcc64.dll"
#else
#define CCAPI_DLL     "krbcc32.dll"
#define KRBCC32_DLL   "krbcc32.dll"
#endif
#define SERVICE_DLL   "advapi32.dll"
#define SECUR32_DLL   "secur32.dll"

//////////////////////////////////////////////////////////////////////////////

#include <loadfuncs-com_err.h>
#include <loadfuncs-krb5.h>
#include <loadfuncs-profile.h>
#include <loadfuncs-krb.h>
#include <loadfuncs-krb524.h>
#include <loadfuncs-lsa.h>

//// CCAPI
/* In order to avoid including the private CCAPI headers */
typedef int cc_int32;

#define CC_API_VER_1 1
#define CC_API_VER_2 2

#define CCACHE_API cc_int32

/*
** The Official Error Codes
*/
#define CC_NOERROR           0
#define CC_BADNAME           1
#define CC_NOTFOUND          2
#define CC_END               3
#define CC_IO                4
#define CC_WRITE             5
#define CC_NOMEM             6
#define CC_FORMAT            7
#define CC_LOCKED            8
#define CC_BAD_API_VERSION   9
#define CC_NO_EXIST          10
#define CC_NOT_SUPP          11
#define CC_BAD_PARM          12
#define CC_ERR_CACHE_ATTACH  13
#define CC_ERR_CACHE_RELEASE 14
#define CC_ERR_CACHE_FULL    15
#define CC_ERR_CRED_VERSION  16

enum {
    CC_CRED_VUNKNOWN = 0,       // For validation
    CC_CRED_V4 = 1,
    CC_CRED_V5 = 2,
    CC_CRED_VMAX = 3            // For validation
};

typedef struct opaque_dll_control_block_type* apiCB;
typedef struct _infoNC {
    char*     name;
    char*     principal;
    cc_int32  vers;
} infoNC;

TYPEDEF_FUNC(
CCACHE_API,
CALLCONV_C,
cc_initialize,
    (
    apiCB** cc_ctx,           // <  DLL's primary control structure.
                              //    returned here, passed everywhere else
    cc_int32 api_version,     // >  ver supported by caller (use CC_API_VER_1)
    cc_int32*  api_supported, // <  if ~NULL, max ver supported by DLL
    const char** vendor       // <  if ~NULL, vendor name in read only C string
    )
);

TYPEDEF_FUNC(
CCACHE_API,
CALLCONV_C,
cc_shutdown,
    (
    apiCB** cc_ctx            // <> DLL's primary control structure. NULL after
    )
);

TYPEDEF_FUNC(
CCACHE_API,
CALLCONV_C,
cc_get_NC_info,
    (
    apiCB* cc_ctx,          // >  DLL's primary control structure
    struct _infoNC*** ppNCi // <  (NULL before call) null terminated,
                            //    list of a structs (free via cc_free_infoNC())
    )
);

TYPEDEF_FUNC(
CCACHE_API,
CALLCONV_C,
cc_free_NC_info,
    (
    apiCB* cc_ctx,
    struct _infoNC*** ppNCi // <  free list of structs returned by
                            //    cc_get_cache_names().  set to NULL on return
    )
);
//// \CCAPI

extern  DWORD AfsAvailable;

// service definitions
typedef SC_HANDLE (WINAPI *FP_OpenSCManagerA)(char *, char *, DWORD);
typedef SC_HANDLE (WINAPI *FP_OpenServiceA)(SC_HANDLE, char *, DWORD);
typedef BOOL (WINAPI *FP_QueryServiceStatus)(SC_HANDLE, LPSERVICE_STATUS);
typedef BOOL (WINAPI *FP_CloseServiceHandle)(SC_HANDLE);

//////////////////////////////////////////////////////////////////////////////

// CCAPI
extern DECL_FUNC_PTR(cc_initialize);
extern DECL_FUNC_PTR(cc_shutdown);
extern DECL_FUNC_PTR(cc_get_NC_info);
extern DECL_FUNC_PTR(cc_free_NC_info);

// krb4 functions
extern DECL_FUNC_PTR(get_krb_err_txt_entry);
extern DECL_FUNC_PTR(k_isinst);
extern DECL_FUNC_PTR(k_isname);
extern DECL_FUNC_PTR(k_isrealm);
extern DECL_FUNC_PTR(kadm_change_your_password);
extern DECL_FUNC_PTR(kname_parse);
extern DECL_FUNC_PTR(krb_get_cred);
extern DECL_FUNC_PTR(krb_get_krbhst);
extern DECL_FUNC_PTR(krb_get_lrealm);
extern DECL_FUNC_PTR(krb_get_pw_in_tkt);
extern DECL_FUNC_PTR(krb_get_tf_realm);
extern DECL_FUNC_PTR(krb_mk_req);
extern DECL_FUNC_PTR(krb_realmofhost);
extern DECL_FUNC_PTR(tf_init);
extern DECL_FUNC_PTR(tf_close);
extern DECL_FUNC_PTR(tf_get_cred);
extern DECL_FUNC_PTR(tf_get_pname);
extern DECL_FUNC_PTR(tf_get_pinst);
extern DECL_FUNC_PTR(LocalHostAddr);
extern DECL_FUNC_PTR(tkt_string);
extern DECL_FUNC_PTR(krb_set_tkt_string);
extern DECL_FUNC_PTR(initialize_krb_error_func);
extern DECL_FUNC_PTR(initialize_kadm_error_table);
extern DECL_FUNC_PTR(dest_tkt);
extern DECL_FUNC_PTR(lsh_LoadKrb4LeashErrorTables); // XXX
extern DECL_FUNC_PTR(krb_in_tkt);
extern DECL_FUNC_PTR(krb_save_credentials);
extern DECL_FUNC_PTR(krb_get_krbconf2);
extern DECL_FUNC_PTR(krb_get_krbrealm2);
extern DECL_FUNC_PTR(krb_life_to_time);

// krb5 functions
extern DECL_FUNC_PTR(krb5_change_password);
extern DECL_FUNC_PTR(krb5_get_init_creds_opt_init);
extern DECL_FUNC_PTR(krb5_get_init_creds_opt_set_tkt_life);
extern DECL_FUNC_PTR(krb5_get_init_creds_opt_set_renew_life);
extern DECL_FUNC_PTR(krb5_get_init_creds_opt_set_forwardable);
extern DECL_FUNC_PTR(krb5_get_init_creds_opt_set_proxiable);
extern DECL_FUNC_PTR(krb5_get_init_creds_opt_set_renew_life);
extern DECL_FUNC_PTR(krb5_get_init_creds_opt_set_address_list);
extern DECL_FUNC_PTR(krb5_get_init_creds_opt_set_change_password_prompt);
extern DECL_FUNC_PTR(krb5_get_init_creds_password);
extern DECL_FUNC_PTR(krb5_get_prompt_types);
extern DECL_FUNC_PTR(krb5_build_principal_ext);
extern DECL_FUNC_PTR(krb5_cc_get_name);
extern DECL_FUNC_PTR(krb5_cc_get_type);
extern DECL_FUNC_PTR(krb5_cc_resolve);
extern DECL_FUNC_PTR(krb5_cc_default);
extern DECL_FUNC_PTR(krb5_cc_default_name);
extern DECL_FUNC_PTR(krb5_cc_set_default_name);
extern DECL_FUNC_PTR(krb5_cc_initialize);
extern DECL_FUNC_PTR(krb5_cc_destroy);
extern DECL_FUNC_PTR(krb5_cc_close);
extern DECL_FUNC_PTR(krb5_cc_copy_creds);
extern DECL_FUNC_PTR(krb5_cc_store_cred);
extern DECL_FUNC_PTR(krb5_cc_retrieve_cred);
extern DECL_FUNC_PTR(krb5_cc_get_principal);
extern DECL_FUNC_PTR(krb5_cc_start_seq_get);
extern DECL_FUNC_PTR(krb5_cc_next_cred);
extern DECL_FUNC_PTR(krb5_cc_end_seq_get);
extern DECL_FUNC_PTR(krb5_cc_remove_cred);
extern DECL_FUNC_PTR(krb5_cc_set_flags);
// extern DECL_FUNC_PTR(krb5_cc_get_type);
extern DECL_FUNC_PTR(krb5_free_context);
extern DECL_FUNC_PTR(krb5_free_cred_contents);
extern DECL_FUNC_PTR(krb5_free_principal);
extern DECL_FUNC_PTR(krb5_get_in_tkt_with_password);
extern DECL_FUNC_PTR(krb5_init_context);
extern DECL_FUNC_PTR(krb5_parse_name);
extern DECL_FUNC_PTR(krb5_timeofday);
extern DECL_FUNC_PTR(krb5_timestamp_to_sfstring);
extern DECL_FUNC_PTR(krb5_unparse_name);
extern DECL_FUNC_PTR(krb5_get_credentials);
extern DECL_FUNC_PTR(krb5_mk_req);
extern DECL_FUNC_PTR(krb5_sname_to_principal);
extern DECL_FUNC_PTR(krb5_get_credentials_renew);
extern DECL_FUNC_PTR(krb5_free_data);
extern DECL_FUNC_PTR(krb5_free_data_contents);
// extern DECL_FUNC_PTR(krb5_get_realm_domain);
extern DECL_FUNC_PTR(krb5_free_unparsed_name);
extern DECL_FUNC_PTR(krb5_os_localaddr);
extern DECL_FUNC_PTR(krb5_copy_keyblock_contents);
extern DECL_FUNC_PTR(krb5_copy_data);
extern DECL_FUNC_PTR(krb5_free_creds);
extern DECL_FUNC_PTR(krb5_build_principal);
extern DECL_FUNC_PTR(krb5_get_renewed_creds);
extern DECL_FUNC_PTR(krb5_free_addresses);
extern DECL_FUNC_PTR(krb5_get_default_config_files);
extern DECL_FUNC_PTR(krb5_free_config_files);
extern DECL_FUNC_PTR(krb5_get_default_realm);
extern DECL_FUNC_PTR(krb5_set_default_realm);
extern DECL_FUNC_PTR(krb5_free_ticket);
extern DECL_FUNC_PTR(krb5_decode_ticket);
extern DECL_FUNC_PTR(krb5_get_host_realm);
extern DECL_FUNC_PTR(krb5_free_host_realm);
extern DECL_FUNC_PTR(krb5_c_random_make_octets);
extern DECL_FUNC_PTR(krb5_free_default_realm);
extern DECL_FUNC_PTR(krb5_string_to_deltat);
extern DECL_FUNC_PTR(krb5_get_error_message);
extern DECL_FUNC_PTR(krb5_free_error_message);
extern DECL_FUNC_PTR(krb5_clear_error_message);

// Krb524 functions
extern DECL_FUNC_PTR(krb524_init_ets);
extern DECL_FUNC_PTR(krb524_convert_creds_kdc);

// ComErr functions
extern DECL_FUNC_PTR(com_err);
extern DECL_FUNC_PTR(error_message);

// Profile functions
extern DECL_FUNC_PTR(profile_init);
extern DECL_FUNC_PTR(profile_flush);
extern DECL_FUNC_PTR(profile_release);
extern DECL_FUNC_PTR(profile_get_subsection_names);
extern DECL_FUNC_PTR(profile_free_list);
extern DECL_FUNC_PTR(profile_get_string);
extern DECL_FUNC_PTR(profile_get_integer);
extern DECL_FUNC_PTR(profile_get_values);
extern DECL_FUNC_PTR(profile_get_relation_names);
extern DECL_FUNC_PTR(profile_clear_relation);
extern DECL_FUNC_PTR(profile_add_relation);
extern DECL_FUNC_PTR(profile_update_relation);
extern DECL_FUNC_PTR(profile_release_string);
extern DECL_FUNC_PTR(profile_rename_section);

// Service functions
extern DECL_FUNC_PTR(OpenSCManagerA);
extern DECL_FUNC_PTR(OpenServiceA);
extern DECL_FUNC_PTR(QueryServiceStatus);
extern DECL_FUNC_PTR(CloseServiceHandle);
extern DECL_FUNC_PTR(LsaNtStatusToWinError);

// LSA Functions
extern DECL_FUNC_PTR(LsaConnectUntrusted);
extern DECL_FUNC_PTR(LsaLookupAuthenticationPackage);
extern DECL_FUNC_PTR(LsaCallAuthenticationPackage);
extern DECL_FUNC_PTR(LsaFreeReturnBuffer);
extern DECL_FUNC_PTR(LsaGetLogonSessionData);

// toolhelp functions
TYPEDEF_FUNC(
    HANDLE,
    WINAPI,
    CreateToolhelp32Snapshot,
    (DWORD, DWORD)
    );
TYPEDEF_FUNC(
    BOOL,
    WINAPI,
    Module32First,
    (HANDLE, LPMODULEENTRY32)
    );
TYPEDEF_FUNC(
    BOOL,
    WINAPI,
    Module32Next,
    (HANDLE, LPMODULEENTRY32)
    );

// psapi functions
TYPEDEF_FUNC(
    DWORD,
    WINAPI,
    GetModuleFileNameExA,
    (HANDLE, HMODULE, LPSTR, DWORD)
    );

TYPEDEF_FUNC(
    BOOL,
    WINAPI,
    EnumProcessModules,
    (HANDLE, HMODULE*, DWORD, LPDWORD)
    );

#define pGetModuleFileNameEx pGetModuleFileNameExA
#define TOOLHELPDLL "kernel32.dll"
#define PSAPIDLL "psapi.dll"

// psapi functions
extern DECL_FUNC_PTR(GetModuleFileNameExA);
extern DECL_FUNC_PTR(EnumProcessModules);

// toolhelp functions
extern DECL_FUNC_PTR(CreateToolhelp32Snapshot);
extern DECL_FUNC_PTR(Module32First);
extern DECL_FUNC_PTR(Module32Next);

khm_int32 init_imports(void);
khm_int32 exit_imports(void);

#endif
