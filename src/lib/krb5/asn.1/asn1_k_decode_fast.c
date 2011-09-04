/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/asn.1/asn1_k_decode_fast.c */
/*
 * Copyright 1994, 2007, 2008, 2010 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 */

#include "asn1_k_decode_macros.h"

asn1_error_code
asn1_decode_fast_armor(asn1buf *buf, krb5_fast_armor *val)
{
    setup();
    val->armor_value.data = NULL;
    {begin_structure();
        get_field(val->armor_type, 0, asn1_decode_int32);
        get_lenfield(val->armor_value.length, val->armor_value.data,
                     1, asn1_decode_charstring);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_data_contents( NULL, &val->armor_value);
    return retval;
}

asn1_error_code
asn1_decode_fast_armor_ptr(asn1buf *buf, krb5_fast_armor **valptr)
{
    decode_ptr(krb5_fast_armor *, asn1_decode_fast_armor);
}

asn1_error_code
asn1_decode_fast_finished(asn1buf *buf, krb5_fast_finished *val)
{
    setup();
    val->client = NULL;
    val->ticket_checksum.contents = NULL;
    {begin_structure();
        get_field(val->timestamp, 0, asn1_decode_kerberos_time);
        get_field(val->usec, 1, asn1_decode_int32);
        alloc_field(val->client);
        get_field(val->client, 2, asn1_decode_realm);
        get_field(val->client, 3, asn1_decode_principal_name);
        get_field(val->ticket_checksum, 4, asn1_decode_checksum);
        end_structure();
    }
    return 0;
error_out:
    krb5_free_principal(NULL, val->client);
    krb5_free_checksum_contents( NULL, &val->ticket_checksum);
    return retval;
}

asn1_error_code
asn1_decode_fast_finished_ptr(asn1buf *buf, krb5_fast_finished **valptr)
{
    decode_ptr( krb5_fast_finished *, asn1_decode_fast_finished);
}
