/*
 * lib/crypto/des/cs_entry.c
 *
 * Copyright 1990, 1991, 1995 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * DES encryption interface file
 */

#include "k5-int.h"
#include "des_int.h"

extern krb5_error_code mit_des_cbc_checksum PROTOTYPE ((
                                                        krb5_pointer ,
							size_t ,
							krb5_pointer ,
							size_t ,
							krb5_checksum FAR * ));

extern krb5_error_code mit_des_cbc_verf_cksum PROTOTYPE ((
							  krb5_checksum FAR *,
							  krb5_pointer ,
							  size_t ,
							  krb5_pointer ,
							  size_t ));

krb5_checksum_entry krb5_des_cbc_cksumtable_entry = {
    0,
    mit_des_cbc_checksum,
    mit_des_cbc_verf_cksum,
    sizeof(mit_des_cblock),
    1,					/* is collision proof */
    1,					/* is keyed */
};
