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
#include<khmsgtypes.h>
#include<khuidefs.h>
#include<utils.h>
#include<commctrl.h>
#include<strsafe.h>
#include<krb5.h>

khm_int32 credtype_id_krb4 = KCDB_CREDTYPE_INVALID;
khm_int32 credtype_id_krb5 = KCDB_CREDTYPE_INVALID;

khm_boolean krb4_initialized = FALSE;
khm_handle krb4_credset = NULL;

/* Kerberos IV stuff */
khm_int32 KHMAPI
krb4_msg_system(khm_int32 msg_type, khm_int32 msg_subtype,
                khm_ui_4 uparam, void * vparam)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    switch(msg_subtype) {
    case KMSG_SYSTEM_INIT:
        {
#ifdef _WIN64
            return KHM_ERROR_NOT_IMPLEMENTED;
#else
            kcdb_credtype ct;
            wchar_t buf[KCDB_MAXCCH_SHORT_DESC];
            size_t cbsize;
            khui_config_node_reg reg;
            wchar_t wshort_desc[KHUI_MAXCCH_SHORT_DESC];
            wchar_t wlong_desc[KHUI_MAXCCH_LONG_DESC];

            /* perform critical registrations and initialization
               stuff */
            ZeroMemory(&ct, sizeof(ct));
            ct.id = KCDB_CREDTYPE_AUTO;
            ct.name = KRB4_CREDTYPE_NAME;

            if(LoadString(hResModule, IDS_KRB4_SHORT_DESC,
                          buf, ARRAYLENGTH(buf)))
                {
                    StringCbLength(buf, KCDB_MAXCB_SHORT_DESC, &cbsize);
                    cbsize += sizeof(wchar_t);
                    ct.short_desc = PMALLOC(cbsize);
                    StringCbCopy(ct.short_desc, cbsize, buf);
                }

            /* even though ideally we should be setting limits
               based KCDB_MAXCB_LONG_DESC, our long description
               actually fits nicely in KCDB_MAXCB_SHORT_DESC */
            if(LoadString(hResModule, IDS_KRB4_LONG_DESC,
                          buf, ARRAYLENGTH(buf)))
                {
                    StringCbLength(buf, KCDB_MAXCB_SHORT_DESC, &cbsize);
                    cbsize += sizeof(wchar_t);
                    ct.long_desc = PMALLOC(cbsize);
                    StringCbCopy(ct.long_desc, cbsize, buf);
                }

            ct.icon = NULL; /* TODO: set a proper icon */
            kmq_create_subscription(krb4_cb, &ct.sub);

            rv = kcdb_credtype_register(&ct, &credtype_id_krb4);

            if(KHM_SUCCEEDED(rv))
                rv = kcdb_credset_create(&krb4_credset);

            if (KHM_SUCCEEDED(rv))
                rv = kcdb_credtype_get_id(KRB5_CREDTYPE_NAME,
                                          &credtype_id_krb5);

            if(ct.short_desc)
                PFREE(ct.short_desc);

            if(ct.long_desc)
                PFREE(ct.long_desc);

            if (KHM_SUCCEEDED(rv)) {
                khui_config_node idents;

                ZeroMemory(&reg, sizeof(reg));

                reg.name = KRB4_CONFIG_NODE_NAME;
                reg.short_desc = wshort_desc;
                reg.long_desc = wlong_desc;
                reg.h_module = hResModule;
                reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_KRB4);
                reg.dlg_proc = krb4_confg_proc;
                reg.flags = 0;

                LoadString(hResModule, IDS_CFG_KRB4_LONG,
                           wlong_desc, ARRAYLENGTH(wlong_desc));
                LoadString(hResModule, IDS_CFG_KRB4_SHORT,
                           wshort_desc, ARRAYLENGTH(wshort_desc));

                khui_cfg_register(NULL, &reg);

                khui_cfg_open(NULL, L"KhmIdentities", &idents);

                ZeroMemory(&reg, sizeof(reg));

                reg.name = KRB4_IDS_CONFIG_NODE_NAME;
                reg.short_desc = wshort_desc;
                reg.long_desc = wlong_desc;
                reg.h_module = hResModule;
                reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_IDS_KRB4);
                reg.dlg_proc = krb4_ids_config_proc;
                reg.flags = KHUI_CNFLAG_SUBPANEL;

                LoadString(hResModule, IDS_CFG_KRB4_SHORT,
                           wlong_desc, ARRAYLENGTH(wlong_desc));
                LoadString(hResModule, IDS_CFG_KRB4_SHORT,
                           wshort_desc, ARRAYLENGTH(wshort_desc));

                khui_cfg_register(idents, &reg);

                ZeroMemory(&reg, sizeof(reg));

                reg.name = KRB4_ID_CONFIG_NODE_NAME;
                reg.short_desc = wshort_desc;
                reg.long_desc = wlong_desc;
                reg.h_module = hResModule;
                reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_ID_KRB4);
                reg.dlg_proc = krb4_id_config_proc;
                reg.flags = KHUI_CNFLAG_SUBPANEL | KHUI_CNFLAG_PLURAL;

                LoadString(hResModule, IDS_CFG_KRB4_SHORT,
                           wlong_desc, ARRAYLENGTH(wlong_desc));
                LoadString(hResModule, IDS_CFG_KRB4_SHORT,
                           wshort_desc, ARRAYLENGTH(wshort_desc));

                khui_cfg_register(idents, &reg);

                khui_cfg_release(idents);

            }

            /* Lookup common data types */
            if(KHM_FAILED(kcdb_type_get_id(TYPENAME_ENCTYPE,
                                           &type_id_enctype))) {
                rv = KHM_ERROR_UNKNOWN;
            }

            if(KHM_FAILED(kcdb_type_get_id(TYPENAME_ADDR_LIST,
                                           &type_id_addr_list))) {
                rv = KHM_ERROR_UNKNOWN;
            }

            if(KHM_FAILED(kcdb_type_get_id(TYPENAME_KRB5_FLAGS,
                                           &type_id_krb5_flags))) {
                rv = KHM_ERROR_UNKNOWN;
            }

            /* Lookup common attributes */
            if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_KEY_ENCTYPE,
                                             &attr_id_key_enctype))) {
                rv = KHM_ERROR_UNKNOWN;
            }

            if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_TKT_ENCTYPE,
                                             &attr_id_tkt_enctype))) {
                rv = KHM_ERROR_UNKNOWN;
            }

            if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_ADDR_LIST,
                                             &attr_id_addr_list))) {
                rv = KHM_ERROR_UNKNOWN;
            }

            if(KHM_FAILED(kcdb_attrib_get_id(ATTRNAME_KRB5_FLAGS,
                                             &attr_id_krb5_flags))) {
                rv = KHM_ERROR_UNKNOWN;
            }

            krb4_initialized = TRUE;

            khm_krb4_set_def_tkt_string();

            khm_krb4_list_tickets();
#endif
        }
        break;

    case KMSG_SYSTEM_EXIT:
#ifdef _WIN64
        /* See above.  On 64-bit platforms, we don't support Krb4 at
           all. */
        return 0;
#else
        if(credtype_id_krb4 >= 0)
            {
                /* basically just unregister the credential type */
                kcdb_credtype_unregister(credtype_id_krb4);

                kcdb_credset_delete(krb4_credset);
            }
        break;
#endif
    }

    return rv;
}

khm_int32 KHMAPI
krb4_msg_cred(khm_int32 msg_type, khm_int32 msg_subtype,
              khm_ui_4 uparam, void * vparam)
{
    khm_int32 rv = KHM_ERROR_SUCCESS;

    switch(msg_subtype) {
    case KMSG_CRED_REFRESH:
        {
            khm_krb4_list_tickets();
        }
        break;

    case KMSG_CRED_DESTROY_CREDS:
        {
            khui_action_context * ctx;
            khm_handle credset;
            khm_size nc_root = 0;
            khm_size nc_sel = 0;

            ctx = (khui_action_context *) vparam;

            /* if all krb4 tickets are selected, then we destroy all
               of them.  Otherwise, we do nothing. */

            kcdb_credset_create(&credset);

            kcdb_credset_extract(credset, ctx->credset,
                                 NULL, credtype_id_krb4);
            kcdb_credset_get_size(credset, &nc_sel);

            kcdb_credset_flush(credset);

            kcdb_credset_extract(credset, NULL,
                                 NULL, credtype_id_krb4);
            kcdb_credset_get_size(credset, &nc_root);

            kcdb_credset_delete(credset);

            if (nc_root == nc_sel) {
                khm_krb4_kdestroy();
            }
        }
        break;

    default:
        if (IS_CRED_ACQ_MSG(msg_subtype))
            return krb4_msg_newcred(msg_type, msg_subtype, uparam, vparam);
    }

    return rv;
}

khm_int32 KHMAPI
krb4_cb(khm_int32 msg_type, khm_int32 msg_subtype,
        khm_ui_4 uparam, void * vparam)
{
    switch(msg_type) {
        case KMSG_SYSTEM:
            return krb4_msg_system(msg_type, msg_subtype, uparam, vparam);
        case KMSG_CRED:
            return krb4_msg_cred(msg_type, msg_subtype, uparam, vparam);
    }
    return KHM_ERROR_SUCCESS;
}
