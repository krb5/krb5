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

#ifndef __KHIMAIRA_KRBAFSCRED_H
#define __KHIMAIRA_KRBAFSCRED_H

#include<windows.h>

#define KHERR_FACILITY L"Krb4Cred"
#define KHERR_FACILITY_ID 65
#define KHERR_HMODULE hResModule

#include<netidmgr.h>

#include<krb4funcs.h>
#include<krb5common.h>
#include<errorfuncs.h>
#include<dynimport.h>

#include<langres.h>
#include<krb4_msgs.h>

#define TYPENAME_ENCTYPE        L"EncType"
#define TYPENAME_ADDR_LIST      L"AddrList"
#define TYPENAME_KRB5_FLAGS     L"Krb5Flags"

#define ATTRNAME_KEY_ENCTYPE    L"KeyEncType"
#define ATTRNAME_TKT_ENCTYPE    L"TktEncType"
#define ATTRNAME_ADDR_LIST      L"AddrList"
#define ATTRNAME_KRB5_FLAGS     L"Krb5Flags"
#define ATTRNAME_RENEW_TILL     L"RenewTill"
#define ATTRNAME_RENEW_FOR      L"RenewFor"

void init_krb();
void exit_krb();

/* globals */
extern kmm_module h_khModule;
extern HMODULE hResModule;
extern HINSTANCE hInstance;

extern khm_int32 type_id_enctype;
extern khm_int32 type_id_addr_list;
extern khm_int32 type_id_krb5_flags;

extern khm_int32 attr_id_key_enctype;
extern khm_int32 attr_id_tkt_enctype;
extern khm_int32 attr_id_addr_list;
extern khm_int32 attr_id_krb5_flags;
extern khm_int32 attr_id_renew_till;
extern khm_int32 attr_id_renew_for;

/* Configuration spaces */
#define CSNAME_KRB4CRED     L"Krb4Cred"
#define CSNAME_PARAMS       L"Parameters"

/* plugin constants */
#define KRB4_PLUGIN_NAME    L"Krb4Cred"

#define KRB4_PLUGIN_DEPS    L"Krb5Cred\0"

#define KRB4_CREDTYPE_NAME  L"Krb4Cred"

#define KRB5_CREDTYPE_NAME  L"Krb5Cred"

#define KRB4_CONFIG_NODE_NAME L"Krb4Config"

#define KRB4_ID_CONFIG_NODE_NAME L"Krb4IdentConfig"
#define KRB4_IDS_CONFIG_NODE_NAME L"Krb4IdentsConfig"

extern khm_handle csp_plugins;
extern khm_handle csp_krbcred;
extern khm_handle csp_params;

extern kconf_schema schema_krbconfig[];

/* other globals */
extern khm_int32 credtype_id_krb4;
extern khm_int32 credtype_id_krb5;

extern khm_boolean krb4_initialized;

extern khm_handle krb4_credset;

/* plugin callbacks */
khm_int32 KHMAPI 
krb4_cb(khm_int32 msg_type, khm_int32 msg_subtype, 
        khm_ui_4 uparam, void * vparam);

INT_PTR CALLBACK
krb4_confg_proc(HWND hwnd,
                UINT uMsg,
                WPARAM wParam,
                LPARAM lParam);

INT_PTR CALLBACK
krb4_ids_config_proc(HWND hwnd,
                     UINT uMsg,
                     WPARAM wParam,
                     LPARAM lParam);

INT_PTR CALLBACK
krb4_id_config_proc(HWND hwnd,
                    UINT uMsg,
                    WPARAM wParam,
                    LPARAM lParam);

khm_int32
krb4_msg_newcred(khm_int32 msg_type, khm_int32 msg_subtype,
                 khm_ui_4 uparam, void * vparam);
#endif
