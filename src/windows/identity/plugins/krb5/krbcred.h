/*
 * Copyright (c) 2004 Massachusetts Institute of Technology
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

#ifndef __KHIMAIRA_KRBAFSCRED_H
#define __KHIMAIRA_KRBAFSCRED_H

#include<windows.h>

/* While we generally pull resources out of hResModule, the message
   strings for all the languages are kept in the main DLL. */
#define KHERR_HMODULE hInstance
#define KHERR_FACILITY k5_facility
#define KHERR_FACILITY_ID 64

#include<khdefs.h>
#include<kcreddb.h>
#include<kmm.h>
#include<kconfig.h>
#include<khuidefs.h>
#include<kherr.h>

#include<krb5funcs.h>
#include<krb5common.h>
#include<errorfuncs.h>
#include<dynimport.h>

#include<langres.h>
#include<datarep.h>
#include<krb5_msgs.h>

#define TYPENAME_ENCTYPE        L"EncType"
#define TYPENAME_ADDR_LIST      L"AddrList"
#define TYPENAME_KRB5_FLAGS     L"Krb5Flags"

#define ATTRNAME_KEY_ENCTYPE    L"KeyEncType"
#define ATTRNAME_TKT_ENCTYPE    L"TktEncType"
#define ATTRNAME_ADDR_LIST      L"AddrList"
#define ATTRNAME_KRB5_FLAGS     L"Krb5Flags"
#define ATTRNAME_KRB5_CCNAME    L"Krb5CCName"

void init_krb();
void exit_krb();
KHMEXP khm_int32 KHMAPI init_module(kmm_module h_module);
KHMEXP khm_int32 KHMAPI exit_module(kmm_module h_module);

/* globals */
extern kmm_module h_khModule;
extern HMODULE hResModule;
extern HINSTANCE hInstance;
extern const wchar_t * k5_facility;

extern khm_int32 type_id_enctype;
extern khm_int32 type_id_addr_list;
extern khm_int32 type_id_krb5_flags;

extern khm_int32 attr_id_key_enctype;
extern khm_int32 attr_id_tkt_enctype;
extern khm_int32 attr_id_addr_list;
extern khm_int32 attr_id_krb5_flags;
extern khm_int32 attr_id_krb5_ccname;

/* Configuration spaces */
#define CSNAME_KRB5CRED      L"Krb5Cred"
#define CSNAME_PARAMS        L"Parameters"
#define CSNAME_PROMPTCACHE   L"PromptCache"

/* plugin constants */
#define KRB5_PLUGIN_NAME    L"Krb5Cred"

#define KRB5_CREDTYPE_NAME  L"Krb5Cred"

extern khm_handle csp_plugins;
extern khm_handle csp_krbcred;
extern khm_handle csp_params;

extern kconf_schema schema_krbconfig[];

/* other globals */
extern khm_int32 credtype_id_krb5;

extern khm_boolean krb5_initialized;

extern khm_handle krb5_credset;

extern khm_handle k5_sub;

extern krb5_context k5_identpro_ctx;

extern BOOL is_k5_identpro;

/* plugin callbacks */
khm_int32 KHMAPI k5_msg_callback(khm_int32 msg_type, khm_int32 msg_subtype, khm_ui_4 uparam, void * vparam);

/* kinit fiber */
typedef struct _fiber_job_t {
    int     command;

    khui_new_creds * nc;
    khui_new_creds_by_type * nct;
    HWND    dialog;

    khm_handle identity;
    char *  principal;
    char *  password;
    char *  ccache;
    krb5_deltat lifetime;
    DWORD   forwardable;
    DWORD   proxiable;
    DWORD   renewable;
    krb5_deltat renew_life;
    DWORD   addressless;
    DWORD   publicIP;

    int     code;
    int     state;
    int     prompt_set;

    BOOL    null_password;
} fiber_job;

extern fiber_job g_fjob;   /* global fiber job object */

#define FIBER_CMD_KINIT     1
#define FIBER_CMD_CANCEL    2
#define FIBER_CMD_CONTINUE  3

#define FIBER_STATE_NONE    0
#define FIBER_STATE_KINIT   1

void 
k5_pp_begin(khui_property_sheet * s);

void 
k5_pp_end(khui_property_sheet * s);

khm_int32 KHMAPI 
k5_msg_cred_dialog(khm_int32 msg_type, 
                   khm_int32 msg_subtype, 
                   khm_ui_4 uparam, 
                   void * vparam);

khm_int32 KHMAPI 
k5_msg_ident(khm_int32 msg_type, 
               khm_int32 msg_subtype, 
               khm_ui_4 uparam, 
               void * vparam);

int 
k5_get_realm_from_nc(khui_new_creds * nc, 
                     wchar_t * buf, 
                     khm_size cch_buf);

void
k5_register_config_panels(void);

void
k5_unregister_config_panels(void);

#endif
