/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * $Id$
 */

#include "gssapiP_generic.h"

/*
 * See krb5/gssapi_krb5.c for a description of the algorithm for
 * encoding an object identifier.
 */

/* Reserved static storage for GSS_oids.  Comments are quotes from RFC 2744. */

#define oids ((gss_OID_desc *)const_oids)
static const gss_OID_desc const_oids[] = {
    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01"},
    /* corresponding to an object-identifier value of
     * {iso(1) member-body(2) United States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) user_name(1)}.  The constant
     * GSS_C_NT_USER_NAME should be initialized to point
     * to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02"},
    /* corresponding to an object-identifier value of
     * {iso(1) member-body(2) United States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) machine_uid_name(2)}.
     * The constant GSS_C_NT_MACHINE_UID_NAME should be
     * initialized to point to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03"},
    /* corresponding to an object-identifier value of
     * {iso(1) member-body(2) United States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) string_uid_name(3)}.
     * The constant GSS_C_NT_STRING_UID_NAME should be
     * initialized to point to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {6, (void *)"\x2b\x06\x01\x05\x06\x02"},
    /* corresponding to an object-identifier value of
     * {iso(1) org(3) dod(6) internet(1) security(5)
     * nametypes(6) gss-host-based-services(2)).  The constant
     * GSS_C_NT_HOSTBASED_SERVICE_X should be initialized to point
     * to that gss_OID_desc.  This is a deprecated OID value, and
     * implementations wishing to support hostbased-service names
     * should instead use the GSS_C_NT_HOSTBASED_SERVICE OID,
     * defined below, to identify such names;
     * GSS_C_NT_HOSTBASED_SERVICE_X should be accepted a synonym
     * for GSS_C_NT_HOSTBASED_SERVICE when presented as an input
     * parameter, but should not be emitted by GSS-API
     * implementations
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {10, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"},
    /* corresponding to an object-identifier value of
     * {iso(1) member-body(2) Unites States(840) mit(113554)
     * infosys(1) gssapi(2) generic(1) service_name(4)}.
     * The constant GSS_C_NT_HOSTBASED_SERVICE should be
     * initialized to point to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {6, (void *)"\x2b\x06\01\x05\x06\x03"},
    /* corresponding to an object identifier value of
     * {1(iso), 3(org), 6(dod), 1(internet), 5(security),
     * 6(nametypes), 3(gss-anonymous-name)}.  The constant
     * and GSS_C_NT_ANONYMOUS should be initialized to point
     * to that gss_OID_desc.
     */

    /*
     * The implementation must reserve static storage for a
     * gss_OID_desc object containing the value */
    {6, (void *)"\x2b\x06\x01\x05\x06\x04"},
    /* corresponding to an object-identifier value of
     * {1(iso), 3(org), 6(dod), 1(internet), 5(security),
     * 6(nametypes), 4(gss-api-exported-name)}.  The constant
     * GSS_C_NT_EXPORT_NAME should be initialized to point
     * to that gss_OID_desc.
     */
    {6, (void *)"\x2b\x06\x01\x05\x06\x06"},
    /* corresponding to an object-identifier value of
     * {1(iso), 3(org), 6(dod), 1(internet), 5(security),
     * 6(nametypes), 6(gss-composite-export)}.  The constant
     * GSS_C_NT_COMPOSITE_EXPORT should be initialized to point
     * to that gss_OID_desc.
     */
    /* GSS_C_INQ_SSPI_SESSION_KEY 1.2.840.113554.1.2.2.5.5 */
    {11, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"},

    /* RFC 5587 attributes, see below */
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x01"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x02"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x03"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x04"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x05"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x06"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x07"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x08"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x09"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0a"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0b"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0c"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0d"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0e"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x0f"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x10"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x11"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x12"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x13"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x14"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x15"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x16"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x17"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x18"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x19"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x1a"},
    {7, (void *)"\x2b\x06\x01\x05\x05\x0d\x1b"},
};

/* Here are the constants which point to the static structure above.
 *
 * Constants of the form GSS_C_NT_* are specified by rfc 2744.
 *
 * Constants of the form gss_nt_* are the original MIT krb5 names
 * found in gssapi_generic.h.  They are provided for compatibility. */

GSS_DLLIMP gss_OID GSS_C_NT_USER_NAME           = oids+0;
GSS_DLLIMP gss_OID gss_nt_user_name             = oids+0;

GSS_DLLIMP gss_OID GSS_C_NT_MACHINE_UID_NAME    = oids+1;
GSS_DLLIMP gss_OID gss_nt_machine_uid_name      = oids+1;

GSS_DLLIMP gss_OID GSS_C_NT_STRING_UID_NAME     = oids+2;
GSS_DLLIMP gss_OID gss_nt_string_uid_name       = oids+2;

GSS_DLLIMP gss_OID GSS_C_NT_HOSTBASED_SERVICE_X = oids+3;
gss_OID gss_nt_service_name_v2                  = oids+3;

GSS_DLLIMP gss_OID GSS_C_NT_HOSTBASED_SERVICE   = oids+4;
GSS_DLLIMP gss_OID gss_nt_service_name          = oids+4;

GSS_DLLIMP gss_OID GSS_C_NT_ANONYMOUS           = oids+5;

GSS_DLLIMP gss_OID GSS_C_NT_EXPORT_NAME         = oids+6;
gss_OID gss_nt_exported_name                    = oids+6;

GSS_DLLIMP gss_OID GSS_C_NT_COMPOSITE_EXPORT    = oids+7;

GSS_DLLIMP gss_OID GSS_C_INQ_SSPI_SESSION_KEY   = oids+8;

GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_CONCRETE     = oids+9;
GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_PSEUDO       = oids+10;
GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_COMPOSITE    = oids+11;
GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_NEGO         = oids+12;
GSS_DLLIMP gss_const_OID GSS_C_MA_MECH_GLUE         = oids+13;
GSS_DLLIMP gss_const_OID GSS_C_MA_NOT_MECH          = oids+14;
GSS_DLLIMP gss_const_OID GSS_C_MA_DEPRECATED        = oids+15;
GSS_DLLIMP gss_const_OID GSS_C_MA_NOT_DFLT_MECH     = oids+16;
GSS_DLLIMP gss_const_OID GSS_C_MA_ITOK_FRAMED       = oids+17;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_INIT         = oids+18;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_TARG         = oids+19;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_INIT_INIT    = oids+20;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_TARG_INIT    = oids+21;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_INIT_ANON    = oids+22;
GSS_DLLIMP gss_const_OID GSS_C_MA_AUTH_TARG_ANON    = oids+23;
GSS_DLLIMP gss_const_OID GSS_C_MA_DELEG_CRED        = oids+24;
GSS_DLLIMP gss_const_OID GSS_C_MA_INTEG_PROT        = oids+25;
GSS_DLLIMP gss_const_OID GSS_C_MA_CONF_PROT         = oids+26;
GSS_DLLIMP gss_const_OID GSS_C_MA_MIC               = oids+27;
GSS_DLLIMP gss_const_OID GSS_C_MA_WRAP              = oids+28;
GSS_DLLIMP gss_const_OID GSS_C_MA_PROT_READY        = oids+29;
GSS_DLLIMP gss_const_OID GSS_C_MA_REPLAY_DET        = oids+30;
GSS_DLLIMP gss_const_OID GSS_C_MA_OOS_DET           = oids+31;
GSS_DLLIMP gss_const_OID GSS_C_MA_CBINDINGS         = oids+32;
GSS_DLLIMP gss_const_OID GSS_C_MA_PFS               = oids+33;
GSS_DLLIMP gss_const_OID GSS_C_MA_COMPRESS          = oids+34;
GSS_DLLIMP gss_const_OID GSS_C_MA_CTX_TRANS         = oids+35;

static gss_OID_set_desc gss_ma_known_attrs_desc = { 27, oids+9 };
gss_OID_set gss_ma_known_attrs = &gss_ma_known_attrs_desc;

#define STRING_BUFFER(x)    { sizeof((x) - 1), (x) }

static struct mech_attr_info_desc {
    gss_OID mech_attr;
    gss_buffer_desc name;
    gss_buffer_desc short_desc;
    gss_buffer_desc long_desc;
} mech_attr_info[] = {
    {
        oids+9,
        STRING_BUFFER("GSS_C_MA_MECH_CONCRETE"),
        STRING_BUFFER("concrete-mech"),
        STRING_BUFFER("Mechanism is neither a pseudo-mechanism nor a "
                      "composite mechanism."),
    },
    {
        oids+10,
        STRING_BUFFER("GSS_C_MA_MECH_PSEUDO"),
        STRING_BUFFER("pseudo-mech"),
        STRING_BUFFER("Mechanism is a pseudo-mechanism."),
    },
    {
        oids+11,
        STRING_BUFFER("GSS_C_MA_MECH_COMPOSITE"),
        STRING_BUFFER("composite-mech"),
        STRING_BUFFER("Mechanism is a composite of other mechanisms."),
    },
    {
        oids+12,
        STRING_BUFFER("GSS_C_MA_MECH_NEGO"),
        STRING_BUFFER("mech-negotiation-mech"),
        STRING_BUFFER("Mechanism negotiates other mechanisms."),
    },
    {
        oids+13,
        STRING_BUFFER("GSS_C_MA_MECH_GLUE"),
        STRING_BUFFER("mech-glue"),
        STRING_BUFFER("OID is not a mechanism but the GSS-API itself."),
    },
    {
        oids+14,
        STRING_BUFFER("GSS_C_MA_NOT_MECH"),
        STRING_BUFFER("not-mech"),
        STRING_BUFFER("Known OID but not a mechanism OID."),
    },
    {
        oids+15,
        STRING_BUFFER("GSS_C_MA_DEPRECATED"),
        STRING_BUFFER("mech-deprecated"),
        STRING_BUFFER("Mechanism is deprecated."),
    },
    {
        oids+16,
        STRING_BUFFER("GSS_C_MA_NOT_DFLT_MECH"),
        STRING_BUFFER("mech-not-default"),
        STRING_BUFFER("Mechanism must not be used as a default mechanism."),
    },
    {
        oids+17,
        STRING_BUFFER("GSS_C_MA_ITOK_FRAMED"),
        STRING_BUFFER("initial-is-framed"),
        STRING_BUFFER("Mechanism's initial contexts are properly framed."),
    },
    {
        oids+18,
        STRING_BUFFER("GSS_C_MA_AUTH_INIT"),
        STRING_BUFFER("auth-init-princ"),
        STRING_BUFFER("Mechanism supports authentication of initiator to "
                      "acceptor."),
    },
    {
        oids+19,
        STRING_BUFFER("GSS_C_MA_AUTH_TARG"),
        STRING_BUFFER("auth-targ-princ"),
        STRING_BUFFER("Mechanism supports authentication of acceptor to "
                      "initiator."),
    },
    {
        oids+20,
        STRING_BUFFER("GSS_C_MA_AUTH_INIT_INIT"),
        STRING_BUFFER("auth-init-princ-initial"),
        STRING_BUFFER("Mechanism supports authentication of initiator using "
                      "initial credentials."),
    },
    {
        oids+21,
        STRING_BUFFER("GSS_C_MA_AUTH_TARG_INIT"),
        STRING_BUFFER("auth-target-princ-initial"),
        STRING_BUFFER("Mechanism supports authentication of acceptor using "
                      "initial credentials."),
    },
    {
        oids+22,
        STRING_BUFFER("GSS_C_MA_AUTH_INIT_ANON"),
        STRING_BUFFER("auth-init-princ-anon"),
        STRING_BUFFER("Mechanism supports GSS_C_NT_ANONYMOUS as an initiator "
                      "name."),
    },
    {
        oids+23,
        STRING_BUFFER("GSS_C_MA_AUTH_TARG_ANON"),
        STRING_BUFFER("auth-targ-princ-anon"),
        STRING_BUFFER("Mechanism supports GSS_C_NT_ANONYMOUS as an acceptor "
                      "name."),
    },
    {
        oids+24,
        STRING_BUFFER("GSS_C_MA_DELEG_CRED"),
        STRING_BUFFER("deleg-cred"),
        STRING_BUFFER("Mechanism supports credential delegation."),
    },
    {
        oids+25,
        STRING_BUFFER("GSS_C_MA_INTEG_PROT"),
        STRING_BUFFER("integ-prot"),
        STRING_BUFFER("Mechanism supports per-message integrity protection."),
    },
    {
        oids+26,
        STRING_BUFFER("GSS_C_MA_CONF_PROT"),
        STRING_BUFFER("conf-prot"),
        STRING_BUFFER("Mechanism supports per-message confidentiality "
                      "protection."),
    },
    {
        oids+27,
        STRING_BUFFER("GSS_C_MA_MIC"),
        STRING_BUFFER("mic"),
        STRING_BUFFER("Mechanism supports Message Integrity Code (MIC) "
                      "tokens."),
    },
    {
        oids+28,
        STRING_BUFFER("GSS_C_MA_WRAP"),
        STRING_BUFFER("wrap"),
        STRING_BUFFER("Mechanism supports wrap tokens."),
    },
    {
        oids+29,
        STRING_BUFFER("GSS_C_MA_PROT_READY"),
        STRING_BUFFER("prot-ready"),
        STRING_BUFFER("Mechanism supports per-message proteciton prior to "
                      "full context establishment."),
    },
    {
        oids+30,
        STRING_BUFFER("GSS_C_MA_REPLAY_DET"),
        STRING_BUFFER("replay-detection"),
        STRING_BUFFER("Mechanism supports replay detection."),
    },
    {
        oids+31,
        STRING_BUFFER("GSS_C_MA_OOS_DET"),
        STRING_BUFFER("oos-detection"),
        STRING_BUFFER("Mechanism supports out-of-sequence detection."),
    },
    {
        oids+32,
        STRING_BUFFER("GSS_C_MA_CBINDINGS"),
        STRING_BUFFER("channel-bindings"),
        STRING_BUFFER("Mechanism supports channel bindings."),
    },
    {
        oids+33,
        STRING_BUFFER("GSS_C_MA_PFS"),
        STRING_BUFFER("pfs"),
        STRING_BUFFER("Mechanism supports Perfect Forward Security."),
    },
    {
        oids+34,
        STRING_BUFFER("GSS_C_MA_COMPRESS"),
        STRING_BUFFER("compress"),
        STRING_BUFFER("Mechanism supports compression of data inputs to "
                      "gss_wrap()."),
    },
    {
        oids+35,
        STRING_BUFFER("GSS_C_MA_CTX_TRANS"),
        STRING_BUFFER("context-transfer"),
        STRING_BUFFER("Mechanism supports security context export/import."),
    },
};

OM_uint32
generic_gss_display_mech_attr(
    OM_uint32         *minor_status,
    gss_const_OID      mech_attr,
    gss_buffer_t       name,
    gss_buffer_t       short_desc,
    gss_buffer_t       long_desc)
{
    size_t i;

    if (name != GSS_C_NO_BUFFER) {
        name->length = 0;
        name->value = NULL;
    }
    if (short_desc != GSS_C_NO_BUFFER) {
        short_desc->length = 0;
        short_desc->value = NULL;
    }
    if (long_desc != GSS_C_NO_BUFFER) {
        long_desc->length = 0;
        long_desc->value = NULL;
    }
    for (i = 0; i < sizeof(mech_attr_info)/sizeof(mech_attr_info[0]); i++) {
        struct mech_attr_info_desc *mai = &mech_attr_info[i];

        if (g_OID_equal(mech_attr, mai->mech_attr)) {
            if (name != GSS_C_NO_BUFFER &&
                !g_make_string_buffer((char *)mai->name.value, name)) {
                *minor_status = ENOMEM;
                return GSS_S_FAILURE;
            }
            if (short_desc != GSS_C_NO_BUFFER &&
                !g_make_string_buffer((char *)mai->short_desc.value,
                                      short_desc)) {
                *minor_status = ENOMEM;
                return GSS_S_FAILURE;
            }
            if (long_desc != GSS_C_NO_BUFFER &&
                !g_make_string_buffer((char *)mai->long_desc.value,
                                      long_desc)) {
                *minor_status = ENOMEM;
                return GSS_S_FAILURE;
            }
            return GSS_S_COMPLETE;
        }
    }

    return GSS_S_BAD_MECH_ATTR;
}

static gss_buffer_desc const_attrs[] = {
    { sizeof("local-login-user") - 1,
      "local-login-user" },
};

GSS_DLLIMP gss_buffer_t GSS_C_ATTR_LOCAL_LOGIN_USER = &const_attrs[0];
