/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * This file contains the source code for krb5_scc_store.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_store_c[] =
"$Id$";
#endif /* !lint && !SABER */


#include "scc.h"

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
krb5_scc_store(id, creds)
   krb5_ccache id;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error_code ret;

     /* Make sure we are writing to the end of the file */
     MAYBE_OPEN (id, SCC_OPEN_RDWR);

     ret = fseek(((krb5_scc_data *) id->data)->file, 0, 2);
     if (ret < 0)
	  return krb5_scc_interpret(errno);

     ret = krb5_scc_store_principal(id, creds->client);
     TCHECK(ret);
     ret = krb5_scc_store_principal(id, creds->server);
     TCHECK(ret);
     ret = krb5_scc_store_keyblock(id, &creds->keyblock);
     TCHECK(ret);
     ret = krb5_scc_store_times(id, &creds->times);
     TCHECK(ret);
     ret = krb5_scc_store_bool(id, &creds->is_skey);
     TCHECK(ret);
     ret = krb5_scc_store_flags(id, &creds->ticket_flags);
     TCHECK(ret);
     ret = krb5_scc_store_addrs(id, creds->addresses);
     TCHECK(ret);
     ret = krb5_scc_store_authdata(id, creds->authdata);
     TCHECK(ret);
     ret = krb5_scc_store_data(id, &creds->ticket);
     TCHECK(ret);
     ret = krb5_scc_store_data(id, &creds->second_ticket);
     TCHECK(ret);

lose:

     MAYBE_CLOSE (id, ret);
     return ret;
#undef TCHECK
}
