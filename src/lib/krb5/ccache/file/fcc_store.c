/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_store.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_store_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

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

     /* Make sure we are writing to the end of the file */
     if (OPENCLOSE(id)) {
	  ret = open(((krb5_fcc_data *) id->data)->filename,
		     O_RDWR | O_APPEND, 0);
	  if (ret < 0)
	       return errno;
	  ((krb5_fcc_data *) id->data)->fd = ret;
     }

     ret = lseek(((krb5_fcc_data *) id->data)->fd, 0, L_XTND);
     if (ret < 0)
	  return errno;

     ret = krb5_fcc_store_principal(id, creds->client);
     TCHECK(ret);
     ret = krb5_fcc_store_principal(id, creds->server);
     TCHECK(ret);
     ret = krb5_fcc_store_keyblock(id, &creds->keyblock);
     TCHECK(ret);
     ret = krb5_fcc_store_times(id, &creds->times);
     TCHECK(ret);
     ret = krb5_fcc_store_bool(id, &creds->is_skey);
     TCHECK(ret);
     ret = krb5_fcc_store_flags(id, &creds->ticket_flags);
     TCHECK(ret);
     ret = krb5_fcc_store_addrs(id, creds->addresses);
     TCHECK(ret);
     ret = krb5_fcc_store_data(id, &creds->ticket);
     TCHECK(ret);
     ret = krb5_fcc_store_data(id, &creds->second_ticket);
     TCHECK(ret);

lose:
          
     if (OPENCLOSE(id)) {
	  close(((krb5_fcc_data *) id->data)->fd);
	  ((krb5_fcc_data *) id->data)->fd = -1;
     }
     return ret;
#undef TCHECK
}
