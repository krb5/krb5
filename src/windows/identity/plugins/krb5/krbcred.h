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

/* While we generally pull resources out of hResModule, the message
   strings for all the languages are kept in the main DLL. */
#define KHERR_HMODULE hInstance
#define KHERR_FACILITY k5_facility
#define KHERR_FACILITY_ID 64

#include<netidmgr.h>

#include<krb5funcs.h>
#include<krb5common.h>
#include<errorfuncs.h>
#include<dynimport.h>

#include<langres.h>
#include<datarep.h>
#include<krb5_msgs.h>

typedef enum tag_k5_lsa_import {
    K5_LSAIMPORT_NEVER = 0,
    K5_LSAIMPORT_ALWAYS = 1,
    K5_LSAIMPORT_MATCH = 2,     /* only when the principal name matches */
} k5_lsa_import;

#define TYPENAME_ENCTYPE        L"EncType"
#define TYPENAME_ADDR_LIST      L"AddrList"
#define TYPENAME_KRB5_FLAGS     L"Krb5Flags"
#define TYPENAME_KRB5_PRINC     L"Krb5Principal"
#define TYPENAME_KVNO           L"Kvno"

#define ATTRNAME_KEY_ENCTYPE    L"KeyEncType"
#define ATTRNAME_TKT_ENCTYPE    L"TktEncType"
#define ATTRNAME_ADDR_LIST      L"AddrList"
#define ATTRNAME_KRB5_FLAGS     L"Krb5Flags"
#define ATTRNAME_KRB5_CCNAME    L"Krb5CCName"
#define ATTRNAME_KVNO           L"Kvno"
#define ATTRNAME_KRB5_IDFLAGS   L"Krb5IDFlags"

/* Flag bits for Krb5IDFlags property */

/* identity was imported from MSLSA: */
#define K5IDFLAG_IMPORTED       0x00000001

void init_krb();
void exit_krb();

/* globals */
extern kmm_module h_khModule;
extern HMODULE hResModule;
extern HINSTANCE hInstance;
extern const wchar_t * k5_facility;

extern khm_int32 type_id_enctype;
extern khm_int32 type_id_addr_list;
extern khm_int32 type_id_krb5_flags;
extern khm_int32 type_id_krb5_princ;
extern khm_int32 type_id_kvno;

extern BOOL      type_regd_krb5_princ;

extern khm_int32 attr_id_key_enctype;
extern khm_int32 attr_id_tkt_enctype;
extern khm_int32 attr_id_addr_list;
extern khm_int32 attr_id_krb5_flags;
extern khm_int32 attr_id_krb5_ccname;
extern khm_int32 attr_id_kvno;
extern khm_int32 attr_id_krb5_idflags;

extern khm_ui_4  k5_commctl_version;

#define IS_COMMCTL6() (k5_commctl_version >= 0x60000)

/* Configuration spaces */
#define CSNAME_KRB5CRED      L"Krb5Cred"
#define CSNAME_PARAMS        L"Parameters"
#define CSNAME_PROMPTCACHE   L"PromptCache"
#define CSNAME_REALMS        L"Realms"

/* plugin constants */
#define KRB5_PLUGIN_NAME    L"Krb5Cred"
#define KRB5_IDENTPRO_NAME  L"Krb5Ident"

#define KRB5_CREDTYPE_NAME  L"Krb5Cred"

/* limits */
/* maximum number of characters in a realm name */
#define K5_MAXCCH_REALM 256

/* maximum number of characters in a host name */
#define K5_MAXCCH_HOST  128

/* maximum number of KDC's per realm */
#define K5_MAX_KDC      64

/* maximum number of domains that map to a realm */
#define K5_MAX_DOMAIN_MAPPINGS 32

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
khm_int32 KHMAPI k5_ident_callback(khm_int32 msg_type, khm_int32 msg_subtype, khm_ui_4 uparam, void * vparam);

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
    wchar_t *error_message;

    BOOL    null_password;
    BOOL    valid_principal;
    BOOL    retry_if_valid_principal;
} fiber_job;

extern fiber_job g_fjob;   /* global fiber job object */

#define FIBER_CMD_KINIT     1
#define FIBER_CMD_CANCEL    2
#define FIBER_CMD_CONTINUE  3

#define FIBER_STATE_NONE          0
#define FIBER_STATE_KINIT         1
#define FIBER_STATE_RETRY_KINIT   2

#define K5_SET_CRED_MSG     WMNC_USER

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

khm_int32
k5_remove_from_LRU(khm_handle identity);

int
k5_get_realm_from_nc(khui_new_creds * nc,
                     wchar_t * buf,
                     khm_size cch_buf);

void
k5_register_config_panels(void);

void
k5_unregister_config_panels(void);

INT_PTR CALLBACK
k5_ccconfig_dlgproc(HWND hwnd,
                    UINT uMsg,
                    WPARAM wParam,
                    LPARAM lParam);

INT_PTR CALLBACK
k5_id_tab_dlgproc(HWND hwndDlg,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam);

INT_PTR CALLBACK
k5_ids_tab_dlgproc(HWND hwnd,
                   UINT uMsg,
                   WPARAM wParam,
                   LPARAM lParam);

#endif
