/*
 * lib/krb5/ccache/file/fcc_store.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_fcc_store.
 */


#include <errno.h>
#include "fcc.h"

#define CHECK(ret) if (ret != KRB5_OK) return ret;

/*
 * Modifies:
 * the file cache
 *
 * Effects:
 * stores creds in the file cred cache
 *
 * Errors:
 * system errors
 * storage failure errors
 */
krb5_error_code
krb5_fcc_store(id, creds)
   krb5_ccache id;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error_code ret;
     krb5_octet octet;

     MAYBE_OPEN(id, FCC_OPEN_RDWR);

     /* Make sure we are writing to the end of the file */
     ret = lseek(((krb5_fcc_data *) id->data)->fd, 0, SEEK_END);
     if (ret < 0) {
	  MAYBE_CLOSE_IGNORE(id);
	  return krb5_fcc_interpret(errno);
     }

     ret = krb5_fcc_store_principal(id, creds->client);
     TCHECK(ret);
     ret = krb5_fcc_store_principal(id, creds->server);
     TCHECK(ret);
     ret = krb5_fcc_store_keyblock(id, &creds->keyblock);
     TCHECK(ret);
     ret = krb5_fcc_store_times(id, &creds->times);
     TCHECK(ret);
     octet = creds->is_skey;
     ret = krb5_fcc_store_octet(id, octet);
     TCHECK(ret);
     ret = krb5_fcc_store_int32(id, creds->ticket_flags);
     TCHECK(ret);
     ret = krb5_fcc_store_addrs(id, creds->addresses);
     TCHECK(ret);
     ret = krb5_fcc_store_authdata(id, creds->authdata);
     TCHECK(ret);
     ret = krb5_fcc_store_data(id, &creds->ticket);
     TCHECK(ret);
     ret = krb5_fcc_store_data(id, &creds->second_ticket);
     TCHECK(ret);

lose:
     MAYBE_CLOSE(id, ret);
     return ret;
#undef TCHECK
}
