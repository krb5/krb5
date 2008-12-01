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

#include<krbcred.h>
#include<kherror.h>

kmm_module h_khModule; /* KMM's handle to this module */
HINSTANCE hInstance;
HMODULE hResModule;    /* HMODULE to the resource library */
const wchar_t * k5_facility = L"Krb5Cred";

khm_int32 type_id_enctype       = -1;
khm_int32 type_id_addr_list     = -1;
khm_int32 type_id_krb5_flags    = -1;
khm_int32 type_id_krb5_princ    = -1;
khm_int32 type_id_kvno          = -1;

BOOL type_regd_enctype      = FALSE;
BOOL type_regd_addr_list    = FALSE;
BOOL type_regd_krb5_flags   = FALSE;
BOOL type_regd_krb5_princ   = FALSE;
BOOL type_regd_kvno         = FALSE;

khm_int32 attr_id_key_enctype   = -1;
khm_int32 attr_id_tkt_enctype   = -1;
khm_int32 attr_id_addr_list     = -1;
khm_int32 attr_id_krb5_flags    = -1;
khm_int32 attr_id_krb5_ccname   = -1;
khm_int32 attr_id_kvno          = -1;
khm_int32 attr_id_krb5_idflags  = -1;

BOOL attr_regd_key_enctype  = FALSE;
BOOL attr_regd_tkt_enctype  = FALSE;
BOOL attr_regd_addr_list    = FALSE;
BOOL attr_regd_krb5_flags   = FALSE;
BOOL attr_regd_krb5_ccname  = FALSE;
BOOL attr_regd_kvno         = FALSE;
BOOL attr_regd_krb5_idflags = FALSE;

khm_handle csp_plugins      = NULL;
khm_handle csp_krbcred   = NULL;
khm_handle csp_params       = NULL;

BOOL is_k5_identpro = TRUE;

khm_ui_4  k5_commctl_version;

kmm_module_locale locales[] = {
    LOCALE_DEF(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US), L"krb5cred_en_us.dll", KMM_MLOC_FLAG_DEFAULT)
};
int n_locales = ARRAYLENGTH(locales);

/* These two should not do anything */
void init_krb() {
}

void exit_krb() {
}

/* called by the NetIDMgr module manager */
KHMEXP_EXP khm_int32 KHMAPI init_module(kmm_module h_module) {
    khm_int32 rv = KHM_ERROR_SUCCESS;
    kmm_plugin_reg pi;
    wchar_t buf[256];

    h_khModule = h_module;

    rv = kmm_set_locale_info(h_module, locales, n_locales);
    if(KHM_SUCCEEDED(rv)) {
        hResModule = kmm_get_resource_hmodule(h_module);
    } else
        goto _exit;

    k5_commctl_version = khm_get_commctl_version(NULL);

    /* register the plugin */
    ZeroMemory(&pi, sizeof(pi));
    pi.name = KRB5_PLUGIN_NAME;
    pi.type = KHM_PITYPE_CRED;
    pi.icon = LoadImage(hResModule, MAKEINTRESOURCE(IDI_PLUGIN),
                        IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR | LR_DEFAULTSIZE);
    pi.flags = 0;
    pi.msg_proc = k5_msg_callback;
    pi.description = buf;
    pi.dependencies = NULL;
    LoadString(hResModule, IDS_PLUGIN_DESC,
               buf, ARRAYLENGTH(buf));
    kmm_provide_plugin(h_module, &pi);

    ZeroMemory(&pi, sizeof(pi));
    pi.name = KRB5_IDENTPRO_NAME;
    pi.type = KHM_PITYPE_IDENT;
    pi.icon = LoadImage(hResModule, MAKEINTRESOURCE(IDI_PLUGIN),
                        IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR | LR_DEFAULTSIZE);
    pi.flags = 0;
    pi.msg_proc = k5_ident_callback;
    pi.description = buf;
    pi.dependencies = KRB5_PLUGIN_NAME L"\0";
    LoadString(hResModule, IDS_IDENTPRO_DESC,
               buf, ARRAYLENGTH(buf));
    kmm_provide_plugin(h_module, &pi);

    if(KHM_FAILED(rv = init_imports()))
        goto _exit;

    if(KHM_FAILED(rv = init_error_funcs()))
        goto _exit;

    /* Register common data types */
    if(KHM_FAILED(kcdb_type_get_id(TYPENAME_ENCTYPE, &type_id_enctype))) {
        kcdb_type type;
        kcdb_type *t32;

        kcdb_type_get_info(KCDB_TYPE_INT32, &t32);

        type.id = KCDB_TYPE_INVALID;
        type.name = TYPENAME_ENCTYPE;
        type.flags = KCDB_TYPE_FLAG_CB_FIXED;
        type.cb_max = t32->cb_max;
        type.cb_min = t32->cb_min;
        type.isValid = t32->isValid;
        type.comp = t32->comp;
        type.dup = t32->dup;
        type.toString = enctype_toString;

        rv = kcdb_type_register(&type, &type_id_enctype);
        kcdb_type_release_info(t32);

        if(KHM_FAILED(rv))
            goto _exit;
        type_regd_enctype = TRUE;
    }

    if(KHM_FAILED(kcdb_type_get_id(TYPENAME_ADDR_LIST, &type_id_addr_list))) {
        kcdb_type type;
        kcdb_type *tdata;

        kcdb_type_get_info(KCDB_TYPE_DATA, &tdata);

        type.id = KCDB_TYPE_INVALID;
        type.name = TYPENAME_ADDR_LIST;
        type.flags = KCDB_TYPE_FLAG_CB_MIN;
        type.cb_min = 0;
        type.cb_max = 0;
        type.isValid = tdata->isValid;
        type.comp = addr_list_comp;
        type.dup = tdata->dup;
        type.toString = addr_list_toString;

        rv = kcdb_type_register(&type, &type_id_addr_list);
        kcdb_type_release_info(tdata);

        if(KHM_FAILED(rv))
            goto _exit;
        type_regd_addr_list = TRUE;
    }

    if(KHM_FAILED(kcdb_type_get_id(TYPENAME_KRB5_FLAGS, &type_id_krb5_flags))) {
        kcdb_type type;
        kcdb_type *t32;

        kcdb_type_get_info(KCDB_TYPE_INT32, &t32);

        type.id = KCDB_TYPE_INVALID;
        type.name = TYPENAME_KRB5_FLAGS;
        type.flags = KCDB_TYPE_FLAG_CB_FIXED;
        type.cb_max = t32->cb_max;
        type.cb_min = t32->cb_min;
        type.isValid = t32->isValid;
        type.comp = t32->comp;
        type.dup = t32->dup;
        type.toString = krb5flags_toString;

        rv = kcdb_type_register(&type, &type_id_krb5_flags);
        kcdb_type_release_info(t32);

        if(KHM_FAILED(rv))
            goto _exit;
        type_regd_krb5_flags = TRUE;
    }

    if (KHM_FAILED(kcdb_type_get_id(TYPENAME_KVNO, &type_id_kvno))) {
        kcdb_type type;
        kcdb_type *t32;

        kcdb_type_get_info(KCDB_TYPE_INT32, &t32);

        type.id = KCDB_TYPE_INVALID;
        type.name = TYPENAME_KVNO;
        type.flags = KCDB_TYPE_FLAG_CB_FIXED;
        type.cb_max = t32->cb_max;
        type.cb_min = t32->cb_min;
        type.isValid = t32->isValid;
        type.comp = t32->comp;
        type.dup = t32->dup;
        type.toString = kvno_toString;

        rv = kcdb_type_register(&type, &type_id_kvno);
        kcdb_type_release_info(t32);

        if (KHM_FAILED(rv))
            goto _exit;

        type_regd_kvno = TRUE;
    }

    /* Register common attributes */
    if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_KEY_ENCTYPE, &attr_id_key_enctype))) {
        kcdb_attrib attrib;
        wchar_t sbuf[KCDB_MAXCCH_SHORT_DESC];
        wchar_t lbuf[KCDB_MAXCCH_SHORT_DESC];
        /* although we are loading a long descriptoin, it still fits
        in the short descriptoin buffer */

        ZeroMemory(&attrib, sizeof(attrib));

        attrib.name = ATTRNAME_KEY_ENCTYPE;
        attrib.id = KCDB_ATTR_INVALID;
        attrib.type = type_id_enctype;
        attrib.flags = KCDB_ATTR_FLAG_TRANSIENT;
        LoadString(hResModule, IDS_KEY_ENCTYPE_SHORT_DESC, sbuf, ARRAYLENGTH(sbuf));
        LoadString(hResModule, IDS_KEY_ENCTYPE_LONG_DESC, lbuf, ARRAYLENGTH(lbuf));
        attrib.short_desc = sbuf;
        attrib.long_desc = lbuf;
        
        rv = kcdb_attrib_register(&attrib, &attr_id_key_enctype);

        if(KHM_FAILED(rv))
            goto _exit;

        attr_regd_key_enctype = TRUE;
    }

    if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_TKT_ENCTYPE, &attr_id_tkt_enctype))) {
        kcdb_attrib attrib;
        wchar_t sbuf[KCDB_MAXCCH_SHORT_DESC];
        wchar_t lbuf[KCDB_MAXCCH_SHORT_DESC];
        /* although we are loading a long descriptoin, it still fits
        in the short descriptoin buffer */

        ZeroMemory(&attrib, sizeof(attrib));

        attrib.name = ATTRNAME_TKT_ENCTYPE;
        attrib.id = KCDB_ATTR_INVALID;
        attrib.type = type_id_enctype;
        attrib.flags = KCDB_ATTR_FLAG_TRANSIENT;
        LoadString(hResModule, IDS_TKT_ENCTYPE_SHORT_DESC, sbuf, ARRAYLENGTH(sbuf));
        LoadString(hResModule, IDS_TKT_ENCTYPE_LONG_DESC, lbuf, ARRAYLENGTH(lbuf));
        attrib.short_desc = sbuf;
        attrib.long_desc = lbuf;
        
        rv = kcdb_attrib_register(&attrib, &attr_id_tkt_enctype);

        if(KHM_FAILED(rv))
            goto _exit;

        attr_regd_tkt_enctype = TRUE;
    }

    if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_ADDR_LIST, &attr_id_addr_list))) {
        kcdb_attrib attrib;
        wchar_t sbuf[KCDB_MAXCCH_SHORT_DESC];
        wchar_t lbuf[KCDB_MAXCCH_SHORT_DESC];
        /* although we are loading a long descriptoin, it still fits
        in the short descriptoin buffer */

        ZeroMemory(&attrib, sizeof(attrib));

        attrib.name = ATTRNAME_ADDR_LIST;
        attrib.id = KCDB_ATTR_INVALID;
        attrib.type = type_id_addr_list;
        attrib.flags = KCDB_ATTR_FLAG_TRANSIENT;
        LoadString(hResModule, IDS_ADDR_LIST_SHORT_DESC, sbuf, ARRAYLENGTH(sbuf));
        LoadString(hResModule, IDS_ADDR_LIST_LONG_DESC, lbuf, ARRAYLENGTH(lbuf));
        attrib.short_desc = sbuf;
        attrib.long_desc = lbuf;
        
        rv = kcdb_attrib_register(&attrib, &attr_id_addr_list);

        if(KHM_FAILED(rv))
            goto _exit;

        attr_regd_addr_list = TRUE;
    }

    if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_KRB5_FLAGS, &attr_id_krb5_flags))) {
        kcdb_attrib attrib;
        wchar_t sbuf[KCDB_MAXCCH_SHORT_DESC];

        /* although we are loading a long descriptoin, it still fits
        in the short descriptoin buffer */

        ZeroMemory(&attrib, sizeof(attrib));

        attrib.name = ATTRNAME_KRB5_FLAGS;
        attrib.id = KCDB_ATTR_INVALID;
        attrib.type = type_id_krb5_flags;
        attrib.flags = KCDB_ATTR_FLAG_TRANSIENT;
        LoadString(hResModule, IDS_KRB5_FLAGS_SHORT_DESC, sbuf, ARRAYLENGTH(sbuf));
        attrib.short_desc = sbuf;
        attrib.long_desc = NULL;
        
        rv = kcdb_attrib_register(&attrib, &attr_id_krb5_flags);

        if(KHM_FAILED(rv))
            goto _exit;

        attr_regd_krb5_flags = TRUE;
    }

    if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_KRB5_CCNAME, &attr_id_krb5_ccname))) {
        kcdb_attrib attrib;
        wchar_t sbuf[KCDB_MAXCCH_SHORT_DESC];
        wchar_t lbuf[KCDB_MAXCCH_SHORT_DESC];
        /* although we are loading a long descriptoin, it still fits
        in the short descriptoin buffer */

        ZeroMemory(&attrib, sizeof(attrib));

        attrib.name = ATTRNAME_KRB5_CCNAME;
        attrib.id = KCDB_ATTR_INVALID;
        attrib.type = KCDB_TYPE_STRING;
        attrib.flags =
	  KCDB_ATTR_FLAG_PROPERTY |
	  KCDB_ATTR_FLAG_TRANSIENT;
        LoadString(hResModule, IDS_KRB5_CCNAME_SHORT_DESC, sbuf, ARRAYLENGTH(sbuf));
        LoadString(hResModule, IDS_KRB5_CCNAME_LONG_DESC, lbuf, ARRAYLENGTH(lbuf));
        attrib.short_desc = sbuf;
        attrib.long_desc = lbuf;
        
        rv = kcdb_attrib_register(&attrib, &attr_id_krb5_ccname);

        if(KHM_FAILED(rv))
            goto _exit;

        attr_regd_krb5_ccname = TRUE;
    }

    if (KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_KVNO, &attr_id_kvno))) {
        kcdb_attrib attrib;
        wchar_t sbuf[KCDB_MAXCCH_SHORT_DESC];
        wchar_t lbuf[KCDB_MAXCCH_LONG_DESC];
        /* although we are loading a long description, it still fits
           in the short description buffer */

        ZeroMemory(&attrib, sizeof(attrib));

        attrib.name = ATTRNAME_KVNO;
        attrib.id = KCDB_ATTR_INVALID;
        attrib.type = type_id_kvno;
        attrib.flags = KCDB_ATTR_FLAG_TRANSIENT;
        LoadString(hResModule, IDS_KVNO_SHORT_DESC, sbuf, ARRAYLENGTH(sbuf));
        LoadString(hResModule, IDS_KVNO_LONG_DESC, lbuf, ARRAYLENGTH(lbuf));
        attrib.short_desc = sbuf;
        attrib.long_desc = lbuf;

        rv = kcdb_attrib_register(&attrib, &attr_id_kvno);

        if (KHM_FAILED(rv))
            goto _exit;

        attr_regd_kvno = TRUE;
    }

    if (KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_KRB5_IDFLAGS, &attr_id_krb5_idflags))) {
        kcdb_attrib attrib;

        ZeroMemory(&attrib, sizeof(attrib));

        attrib.name = ATTRNAME_KRB5_IDFLAGS;
        attrib.id = KCDB_ATTR_INVALID;
        attrib.type = KCDB_TYPE_INT32;
        attrib.flags = KCDB_ATTR_FLAG_PROPERTY |
            KCDB_ATTR_FLAG_HIDDEN;
        /* we don't bother localizing these strings since the
           attribute is hidden.  The user will not see these
           descriptions anyway. */
        attrib.short_desc = L"Krb5 ID flags";
        attrib.long_desc = L"Kerberos 5 Identity Flags";

        rv = kcdb_attrib_register(&attrib, &attr_id_krb5_idflags);

        if (KHM_FAILED(rv))
            goto _exit;

        attr_regd_krb5_idflags = TRUE;
    }

    rv = kmm_get_plugins_config(0, &csp_plugins);
    if(KHM_FAILED(rv)) goto _exit;

    rv = khc_load_schema(csp_plugins, schema_krbconfig);
    if(KHM_FAILED(rv)) goto _exit;

    rv = khc_open_space(csp_plugins, CSNAME_KRB5CRED, 0, &csp_krbcred);
    if(KHM_FAILED(rv)) goto _exit;

    rv = khc_open_space(csp_krbcred, CSNAME_PARAMS, 0, &csp_params);
    if(KHM_FAILED(rv)) goto _exit;

_exit:
    return rv;
}

/* called by the NetIDMgr module manager */
KHMEXP_EXP khm_int32 KHMAPI exit_module(kmm_module h_module) {
    exit_imports();
    exit_error_funcs();

    if(attr_regd_key_enctype)
        kcdb_attrib_unregister(attr_id_key_enctype);
    if(attr_regd_tkt_enctype)
        kcdb_attrib_unregister(attr_id_tkt_enctype);
    if(attr_regd_addr_list)
        kcdb_attrib_unregister(attr_id_addr_list);
    if(attr_regd_krb5_flags)
        kcdb_attrib_unregister(attr_id_krb5_flags);
    if(attr_regd_krb5_ccname)
        kcdb_attrib_unregister(attr_id_krb5_ccname);
    if(attr_regd_kvno)
        kcdb_attrib_unregister(attr_id_kvno);
    if(attr_regd_krb5_idflags)
        kcdb_attrib_unregister(attr_id_krb5_idflags);

    if(type_regd_enctype)
        kcdb_type_unregister(type_id_enctype);
    if(type_regd_addr_list)
        kcdb_type_unregister(type_id_addr_list);
    if(type_regd_krb5_flags)
        kcdb_type_unregister(type_id_krb5_flags);
    if(type_regd_kvno)
        kcdb_type_unregister(type_id_kvno);

    if(csp_params) {
        khc_close_space(csp_params);
        csp_params = NULL;
    }

    if(csp_krbcred) {
        khc_close_space(csp_krbcred);
        csp_krbcred = NULL;
    }

    if(csp_plugins) {
        khc_unload_schema(csp_plugins, schema_krbconfig);
        khc_close_space(csp_plugins);
        csp_plugins = NULL;
    }

    return KHM_ERROR_SUCCESS; /* the return code is ignored */
}

BOOL WINAPI DllMain(
  HINSTANCE hinstDLL,
  DWORD fdwReason,
  LPVOID lpvReserved
)
{
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:
            hInstance = hinstDLL;
            init_krb();
            break;
        case DLL_PROCESS_DETACH:
            exit_krb();
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}
