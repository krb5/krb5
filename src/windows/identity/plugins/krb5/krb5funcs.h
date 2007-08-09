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

/* Adapted from multiple Leash header files */

#ifndef __KHIMAIRA_KRB5FUNCS_H
#define __KHIMAIRA_KRB5FUNCS_H

#include<stdlib.h>
#include<krb5.h>

#include <windows.h>
#define SECURITY_WIN32
#include <security.h>

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

#include <krb5common.h>

#define LEASH_DEBUG_CLASS_GENERIC   0
#define LEASH_DEBUG_CLASS_KRB4      1
#define LEASH_DEBUG_CLASS_KRB4_APP  2

#define LEASH_PRIORITY_LOW  0
#define LEASH_PRIORITY_HIGH 1

#define KRB5_DEFAULT_LIFE            60*60*10 /* 10 hours */

#define KRB5_MAXCCH_CCNAME           1024

#define KRB5_CONF_YES                "yes"
#define KRB5_CONF_NO                 "no"

typedef struct tag_k5params {

    khm_int32   source_reg;     /* flags indicating which fields were
                                   retrieved using the registry */
    khm_int32   source_prof;    /* flags indicating which fields were
                                   retrieved using krb5.ini */

    khm_boolean renewable;
    khm_boolean forwardable;
    khm_boolean proxiable;
    khm_boolean addressless;

    khm_ui_4    publicIP;

    krb5_deltat lifetime;
    krb5_deltat lifetime_min;
    krb5_deltat lifetime_max;

    krb5_deltat renew_life;
    krb5_deltat renew_life_min;
    krb5_deltat renew_life_max;

} k5_params;

#define K5PARAM_F_RENEW   0x00000001
#define K5PARAM_F_FORW    0x00000002
#define K5PARAM_F_PROX    0x00000004
#define K5PARAM_F_ADDL    0x00000008
#define K5PARAM_F_PUBIP   0x00000010
#define K5PARAM_F_LIFE    0x00000020
#define K5PARAM_F_RLIFE   0x00000040
#define K5PARAM_F_LIFE_L  0x00000080
#define K5PARAM_F_LIFE_H  0x00000100
#define K5PARAM_F_RLIFE_L 0x00000200
#define K5PARAM_F_RLIFE_H 0x00000400

#define K5PARAM_FM_ALL    0x000007ff
#define K5PARAM_FM_PROF   0x0000007f
 
/* Credential and principal operations */

BOOL 
khm_krb5_ms2mit(char * match_princ,
                BOOL   match_realm,
                BOOL   save_creds,
                khm_handle * ret_ident);

int
khm_krb5_kinit(krb5_context       alt_ctx,
               char *             principal_name,
               char *             password,
               char *             ccache,
               krb5_deltat        lifetime,
               DWORD              forwardable,
               DWORD              proxiable,
               krb5_deltat        renew_life,
               DWORD              addressless,
               DWORD              publicIP,
               krb5_prompter_fct  prompter,
               void *             p_data);

long
khm_krb5_changepwd(char * principal,
                   char * password,
                   char * newpassword,
                   char** error_str);

int
khm_krb5_destroy_by_credset(khm_handle p_cs);

int
khm_krb5_destroy_identity(khm_handle identity);

long
khm_convert524(krb5_context ctx);

int
khm_krb5_renew_cred(khm_handle cred);

int 
khm_krb5_renew_ident(khm_handle identity);

long 
khm_krb5_list_tickets(krb5_context *krbv5Context);

long
khm_krb5_copy_ccache_by_name(krb5_context in_ctx,
                             wchar_t * wscc_dest,
                             wchar_t * wscc_src);

long
khm_krb5_get_temp_ccache(krb5_context ctx,
                         krb5_ccache * cc);

khm_int32 KHMAPI
khm_krb5_creds_is_equal(khm_handle vcred1, khm_handle vcred2, void * dummy);


/* Configuration */

BOOL 
khm_krb5_get_profile_file(LPSTR confname, UINT szConfname);

BOOL 
khm_krb5_get_temp_profile_file(LPSTR confname, UINT szConfname);

wchar_t * 
khm_krb5_get_default_realm(void);

long
khm_krb5_set_default_realm(wchar_t * realm);

wchar_t * 
khm_krb5_get_realm_list(void);

khm_int32
khm_krb5_get_identity_config(khm_handle ident,
                             khm_int32 flags,
                             khm_handle * ret_csp);

void
khm_krb5_set_identity_flags(khm_handle identity,
                            khm_int32  flag_mask,
                            khm_int32  flag_value);

khm_int32
khm_krb5_get_identity_flags(khm_handle identity);

khm_int32
khm_krb5_set_identity_params(khm_handle ident, const k5_params * p);

khm_int32
khm_krb5_get_identity_params(khm_handle ident, k5_params * p);

/* Utility */

wchar_t * 
khm_get_realm_from_princ(wchar_t * princ);

long
khm_krb5_canon_cc_name(wchar_t * wcc_name,
                       size_t cb_cc_name);

int 
khm_krb5_cc_name_cmp(const wchar_t * cc_name_1,
                     const wchar_t * cc_name_2);

int
khm_krb5_parse_boolean(const char *s, khm_boolean * b);

#endif
