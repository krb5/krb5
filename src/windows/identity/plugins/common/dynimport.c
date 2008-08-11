/*
* Copyright (c) 2005 Massachusetts Institute of Technology
* Copyright (c) 2007 Secure Endpoints Inc.
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

#include<windows.h>
#include<netidmgr.h>
#include<dynimport.h>

HINSTANCE hKrb4 = 0;
HINSTANCE hKrb5 = 0;
HINSTANCE hKrb524 = 0;
HINSTANCE hSecur32 = 0;
HINSTANCE hComErr = 0;
HINSTANCE hService = 0;
HINSTANCE hProfile = 0;
HINSTANCE hPsapi = 0; 
HINSTANCE hToolHelp32 = 0; 
HINSTANCE hCCAPI = 0;

DWORD     AfsAvailable = 0;

// CCAPI
DECL_FUNC_PTR(cc_initialize);
DECL_FUNC_PTR(cc_shutdown);
DECL_FUNC_PTR(cc_get_NC_info);
DECL_FUNC_PTR(cc_free_NC_info);

// krb4 functions
DECL_FUNC_PTR(get_krb_err_txt_entry);
DECL_FUNC_PTR(k_isinst);
DECL_FUNC_PTR(k_isname);
DECL_FUNC_PTR(k_isrealm);
DECL_FUNC_PTR(kadm_change_your_password);
DECL_FUNC_PTR(kname_parse);
DECL_FUNC_PTR(krb_get_cred);
DECL_FUNC_PTR(krb_get_krbhst);
DECL_FUNC_PTR(krb_get_lrealm);
DECL_FUNC_PTR(krb_get_pw_in_tkt);
DECL_FUNC_PTR(krb_get_tf_realm);
DECL_FUNC_PTR(krb_mk_req);
DECL_FUNC_PTR(krb_realmofhost);
DECL_FUNC_PTR(tf_init);
DECL_FUNC_PTR(tf_close);
DECL_FUNC_PTR(tf_get_cred);
DECL_FUNC_PTR(tf_get_pname);
DECL_FUNC_PTR(tf_get_pinst);
DECL_FUNC_PTR(LocalHostAddr);
DECL_FUNC_PTR(tkt_string);
DECL_FUNC_PTR(krb_set_tkt_string);
DECL_FUNC_PTR(initialize_krb_error_func);
DECL_FUNC_PTR(initialize_kadm_error_table);
DECL_FUNC_PTR(dest_tkt);
DECL_FUNC_PTR(krb_in_tkt);
DECL_FUNC_PTR(krb_save_credentials);
DECL_FUNC_PTR(krb_get_krbconf2);
DECL_FUNC_PTR(krb_get_krbrealm2);
DECL_FUNC_PTR(krb_life_to_time);

// krb5 functions
DECL_FUNC_PTR(krb5_change_password);
DECL_FUNC_PTR(krb5_get_init_creds_opt_init);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_tkt_life);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_renew_life);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_forwardable);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_proxiable);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_address_list);
DECL_FUNC_PTR(krb5_get_init_creds_opt_set_change_password_prompt);
DECL_FUNC_PTR(krb5_get_init_creds_password);
DECL_FUNC_PTR(krb5_get_prompt_types);
DECL_FUNC_PTR(krb5_build_principal_ext);
DECL_FUNC_PTR(krb5_cc_get_name);
DECL_FUNC_PTR(krb5_cc_get_type);
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
// DECL_FUNC_PTR(krb5_cc_get_type);
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
// DECL_FUNC_PTR(krb5_get_realm_domain);
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
DECL_FUNC_PTR(krb5_set_default_realm);
DECL_FUNC_PTR(krb5_free_ticket);
DECL_FUNC_PTR(krb5_decode_ticket);
DECL_FUNC_PTR(krb5_get_host_realm);
DECL_FUNC_PTR(krb5_free_host_realm);
DECL_FUNC_PTR(krb5_c_random_make_octets);
DECL_FUNC_PTR(krb5_free_addresses);
DECL_FUNC_PTR(krb5_free_default_realm);
DECL_FUNC_PTR(krb5_string_to_deltat);
DECL_FUNC_PTR(krb5_get_error_message);
DECL_FUNC_PTR(krb5_free_error_message);
DECL_FUNC_PTR(krb5_clear_error_message);

// Krb524 functions
DECL_FUNC_PTR(krb524_init_ets);
DECL_FUNC_PTR(krb524_convert_creds_kdc);

// ComErr functions
DECL_FUNC_PTR(com_err);
DECL_FUNC_PTR(error_message);

// Profile functions
DECL_FUNC_PTR(profile_init);    
DECL_FUNC_PTR(profile_flush);
DECL_FUNC_PTR(profile_release); 
DECL_FUNC_PTR(profile_get_subsection_names);
DECL_FUNC_PTR(profile_free_list);
DECL_FUNC_PTR(profile_get_string);
DECL_FUNC_PTR(profile_get_integer);
DECL_FUNC_PTR(profile_get_values);
DECL_FUNC_PTR(profile_get_relation_names);
DECL_FUNC_PTR(profile_clear_relation);
DECL_FUNC_PTR(profile_add_relation);
DECL_FUNC_PTR(profile_update_relation);
DECL_FUNC_PTR(profile_release_string);
DECL_FUNC_PTR(profile_rename_section);

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

FUNC_INFO k4_fi[] = {
    MAKE_FUNC_INFO(get_krb_err_txt_entry),
    MAKE_FUNC_INFO(k_isinst),
    MAKE_FUNC_INFO(k_isname),
    MAKE_FUNC_INFO(k_isrealm),
    MAKE_FUNC_INFO(kadm_change_your_password),
    MAKE_FUNC_INFO(kname_parse),
    MAKE_FUNC_INFO(krb_get_cred),
    MAKE_FUNC_INFO(krb_get_krbhst),
    MAKE_FUNC_INFO(krb_get_lrealm),
    MAKE_FUNC_INFO(krb_get_pw_in_tkt),
    MAKE_FUNC_INFO(krb_get_tf_realm),
    MAKE_FUNC_INFO(krb_mk_req),
    MAKE_FUNC_INFO(krb_realmofhost),
    MAKE_FUNC_INFO(tf_init),
    MAKE_FUNC_INFO(tf_close),
    MAKE_FUNC_INFO(tf_get_cred),
    MAKE_FUNC_INFO(tf_get_pname),
    MAKE_FUNC_INFO(tf_get_pinst),
    MAKE_FUNC_INFO(LocalHostAddr),
    MAKE_FUNC_INFO(tkt_string),
    MAKE_FUNC_INFO(krb_set_tkt_string),
    MAKE_FUNC_INFO(initialize_krb_error_func),
    MAKE_FUNC_INFO(initialize_kadm_error_table),
    MAKE_FUNC_INFO(dest_tkt),
    /*        MAKE_FUNC_INFO(lsh_LoadKrb4LeashErrorTables), */// XXX
    MAKE_FUNC_INFO(krb_in_tkt),
    MAKE_FUNC_INFO(krb_save_credentials),
    MAKE_FUNC_INFO(krb_get_krbconf2),
    MAKE_FUNC_INFO(krb_get_krbrealm2),
    MAKE_FUNC_INFO(krb_life_to_time),
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
    MAKE_FUNC_INFO(krb5_get_init_creds_opt_set_change_password_prompt),
    MAKE_FUNC_INFO(krb5_get_init_creds_password),
    MAKE_FUNC_INFO(krb5_get_prompt_types),
    MAKE_FUNC_INFO(krb5_build_principal_ext),
    MAKE_FUNC_INFO(krb5_cc_get_name),
    MAKE_FUNC_INFO(krb5_cc_get_type),
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
    // MAKE_FUNC_INFO(krb5_cc_get_type),
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
    //  MAKE_FUNC_INFO(krb5_get_realm_domain),
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
    MAKE_FUNC_INFO(krb5_set_default_realm),
    MAKE_FUNC_INFO(krb5_free_ticket),
    MAKE_FUNC_INFO(krb5_decode_ticket),
    MAKE_FUNC_INFO(krb5_get_host_realm),
    MAKE_FUNC_INFO(krb5_free_host_realm),
    MAKE_FUNC_INFO(krb5_c_random_make_octets),
    MAKE_FUNC_INFO(krb5_free_default_realm),
    MAKE_FUNC_INFO(krb5_string_to_deltat),
    MAKE_FUNC_INFO(krb5_get_error_message),
    MAKE_FUNC_INFO(krb5_free_error_message),
    MAKE_FUNC_INFO(krb5_clear_error_message),
    END_FUNC_INFO
};

FUNC_INFO k524_fi[] = {
    MAKE_FUNC_INFO(krb524_init_ets),
    MAKE_FUNC_INFO(krb524_convert_creds_kdc),
    END_FUNC_INFO
};

FUNC_INFO profile_fi[] = {
    MAKE_FUNC_INFO(profile_init),
    MAKE_FUNC_INFO(profile_flush),
    MAKE_FUNC_INFO(profile_release), 
    MAKE_FUNC_INFO(profile_get_subsection_names),
    MAKE_FUNC_INFO(profile_free_list),
    MAKE_FUNC_INFO(profile_get_string),
    MAKE_FUNC_INFO(profile_get_integer),
    MAKE_FUNC_INFO(profile_get_values),
    MAKE_FUNC_INFO(profile_get_relation_names),
    MAKE_FUNC_INFO(profile_clear_relation),
    MAKE_FUNC_INFO(profile_add_relation),
    MAKE_FUNC_INFO(profile_update_relation),
    MAKE_FUNC_INFO(profile_release_string),
    MAKE_FUNC_INFO(profile_rename_section),
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

// psapi functions
DECL_FUNC_PTR(GetModuleFileNameExA);
DECL_FUNC_PTR(EnumProcessModules);

FUNC_INFO psapi_fi[] = {
    MAKE_FUNC_INFO(GetModuleFileNameExA),
        MAKE_FUNC_INFO(EnumProcessModules),
        END_FUNC_INFO
};

// toolhelp functions
DECL_FUNC_PTR(CreateToolhelp32Snapshot);
DECL_FUNC_PTR(Module32First);
DECL_FUNC_PTR(Module32Next);

FUNC_INFO toolhelp_fi[] = {
    MAKE_FUNC_INFO(CreateToolhelp32Snapshot),
        MAKE_FUNC_INFO(Module32First),
        MAKE_FUNC_INFO(Module32Next),
        END_FUNC_INFO
};

khm_int32 init_imports(void) {
    OSVERSIONINFO osvi;
    int imp_rv = 1;

#define CKRV(m)           \
  do {                    \
    if(!imp_rv) {         \
      _reportf(L"Can't locate all required exports from module [%S]", (m)); \
      goto _err_ret;      \
    }                     \
 } while (FALSE)

#ifndef _WIN64
    imp_rv = LoadFuncs(KRB4_DLL, k4_fi, &hKrb4, 0, 1, 0, 0);
    CKRV(KRB4_DLL);
#endif

    imp_rv = LoadFuncs(KRB5_DLL, k5_fi, &hKrb5, 0, 1, 0, 0);
    CKRV(KRB5_DLL);

    imp_rv = LoadFuncs(COMERR_DLL, ce_fi, &hComErr, 0, 0, 1, 0);
    CKRV(COMERR_DLL);

    imp_rv = LoadFuncs(SERVICE_DLL, service_fi, &hService, 0, 1, 0, 0);
    CKRV(SERVICE_DLL);

    imp_rv = LoadFuncs(SECUR32_DLL, lsa_fi, &hSecur32, 0, 1, 1, 1);
    CKRV(SECUR32_DLL);

#ifndef _WIN64
    imp_rv = LoadFuncs(KRB524_DLL, k524_fi, &hKrb524, 0, 1, 1, 1);
    CKRV(KRB524_DLL);
#endif

    imp_rv = LoadFuncs(PROFILE_DLL, profile_fi, &hProfile, 0, 1, 0, 0);
    CKRV(PROFILE_DLL);

    imp_rv = LoadFuncs(CCAPI_DLL, ccapi_fi, &hCCAPI, 0, 1, 0, 0);
    /* CCAPI_DLL is optional.  No error check. */

    memset(&osvi, 0, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);

    // XXX: We should really use feature testing, first
    // checking for CreateToolhelp32Snapshot.  If that's
    // not around, we try the psapi stuff.
    //
    // Only load LSA functions if on NT/2000/XP
    if(osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
    {
        // Windows 9x
        imp_rv = LoadFuncs(TOOLHELPDLL, toolhelp_fi, &hToolHelp32, 0, 1, 0, 0);
        CKRV(TOOLHELPDLL);

        hPsapi = 0;
    }             
    else if(osvi.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        // Windows NT
        imp_rv = LoadFuncs(PSAPIDLL, psapi_fi, &hPsapi, 0, 1, 0, 0);
        CKRV(PSAPIDLL);

        hToolHelp32 = 0;
    }

    AfsAvailable = TRUE; //afscompat_init();

    return KHM_ERROR_SUCCESS;

 _err_ret:
    return KHM_ERROR_NOT_FOUND;
}

khm_int32 exit_imports(void) {
    //afscompat_close();

    if (hKrb4)
        FreeLibrary(hKrb4);
    if (hKrb5)
        FreeLibrary(hKrb5);
    if (hProfile)
        FreeLibrary(hProfile);
    if (hComErr)
        FreeLibrary(hComErr);
    if (hService)
        FreeLibrary(hService);
    if (hSecur32)
        FreeLibrary(hSecur32);
    if (hKrb524)
        FreeLibrary(hKrb524);
    if (hPsapi)
        FreeLibrary(hPsapi);
    if (hToolHelp32)
        FreeLibrary(hToolHelp32);

    return KHM_ERROR_SUCCESS;
}

int (*Lcom_err)(LPSTR,long,LPSTR,...);
LPSTR (*Lerror_message)(long);
LPSTR (*Lerror_table_name)(long);

void Leash_load_com_err_callback(FARPROC ce,
                                 FARPROC em,
                                 FARPROC etn)
{
    Lcom_err = (int (*)(LPSTR,long,LPSTR,...)) ce;
    Lerror_message = (LPSTR (*)(long))         em;
    Lerror_table_name = (LPSTR (*)(long))      etn;
}
