/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * spnego-asn1.h
 *
 * Copyright (C) 2002 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * This file contains structure definitions
 * for the SPNEGO GSSAPI mechanism (RFC 2478).  This file is
 *an internal interface between the GSSAPI library  and the ASN.1
 *encoders/decoders for the SPNEGO structures in the krb5 library.
 */


#ifndef _KRB5_SPNEGO_ASN1_H_
#define _KRB5_SPNEGO_ASN1_h_

#include "k5-int.h"

/* Context flags recognized by SPNEGO*/
enum {
    SPNEGO_DELEG_FLAG = 0x80,
    SPNEGO_MUTUAL_FLAG = 0x40,
    SPNEGO_ANON_FLAG=0x20,
    SPNEGO_CONF_FLAG = 0x10
};

/* Results of a negotiation*/
enum {
    SPNEGO_ACCEPT_COMPLETED = 0,
    SPNEGO_ACCEPT_INCOMPLETE = 1,
    SPNEGO_REJECT = 2,
    SPNEGO_UNSPEC_RESULT = 3
};

typedef krb5_data spnego_oid;

typedef struct _spnego_initiator_token {
    spnego_oid **mechanisms;
    krb5_int32 requested_flags;
    krb5_data mech_token;
    krb5_data mechlist_mic;
} spnego_initiator_token;

typedef struct _spnego_acceptor_token {
    int neg_result;
    spnego_oid supported_mech;
    krb5_data response_token;
    krb5_data mechlist_mic;
} spnego_acceptor_token;

/*
 * SPNEGO_PROTOTYPES should be defined in the modules implementing
 * SPNEGO functions  and in the module implementing the accessor
 * initializer.  All other modules should access these functions
 * through the accessor interface.
 */

#ifdef SPNEGO_PROTOTYPES

krb5_error_code krb5int_encode_spnego_acceptor_token
(krb5_context , spnego_acceptor_token *,
 krb5_data **);

krb5_error_code krb5int_encode_spnego_initiator_token
(krb5_context, spnego_initiator_token *,
 krb5_data **out);
#endif /*SPNEGO_ASN1_PROTOTYPES*/

#endif /*_KRB5_SPNEGO_ASN1_H_*/
