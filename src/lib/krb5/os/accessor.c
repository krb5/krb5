/*
 * lib/krb5/os/accessor.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * 
*/

#define NEED_SOCKETS
#include "k5-int.h"
#include "os-proto.h"

krb5_error_code KRB5_CALLCONV
krb5int_accessor(krb5int_access *internals, krb5_int32 version)
{
  if (version == KRB5INT_ACCESS_VERSION)
  {
    krb5int_access internals_temp;
    internals_temp.free_addrlist = krb5int_free_addrlist;
    internals_temp.krb5_hmac = krb5_hmac;
    internals_temp.md5_hash_provider = &krb5int_hash_md5;
    internals_temp.arcfour_enc_provider = &krb5int_enc_arcfour;
    internals_temp.locate_server = &krb5int_locate_server;
    internals_temp.sendto_udp = &krb5int_sendto;
    internals_temp.add_host_to_list = krb5int_add_host_to_list;
#ifdef KRB5_DNS_LOOKUP
    internals_temp.make_srv_query_realm = krb5int_make_srv_query_realm;
    internals_temp.free_srv_dns_data = krb5int_free_srv_dns_data;
    internals_temp.use_dns_kdc = _krb5_use_dns_kdc;
#else
    internals_temp.make_srv_query_realm = 0;
    internals_temp.free_srv_dns_data = 0;
    internals_temp.use_dns_kdc = 0;
#endif
#ifdef KRB5_KRB4_COMPAT
    internals_temp.krb_life_to_time = krb5int_krb_life_to_time;
    internals_temp.krb_time_to_life = krb5int_krb_time_to_life;
    internals_temp.krb524_encode_v4tkt = krb5int_encode_v4tkt;
#else
    internals_temp.krb_life_to_time = 0;
    internals_temp.krb_time_to_life = 0;
    internals_temp.krb524_encode_v4tkt = 0;
#endif
    internals_temp.krb5int_c_mandatory_cksumtype = krb5int_c_mandatory_cksumtype;
    internals_temp.krb5_ser_pack_int64 = krb5_ser_pack_int64;
    internals_temp.krb5_ser_unpack_int64 = krb5_ser_unpack_int64;
    *internals = internals_temp;
    return 0;
  }
  return KRB5_OBSOLETE_FN;
}
