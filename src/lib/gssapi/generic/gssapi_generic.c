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

    /* GSS_C_INQ_SSPI_SESSION_KEY 1.2.840.113554.1.2.2.5.5 */
    {11, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"},
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

GSS_DLLIMP gss_OID GSS_C_INQ_SSPI_SESSION_KEY   = oids+7;
