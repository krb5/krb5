/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_scc_initialize.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_init_c[] =
"$Id$";
#endif /* !lint && !SABER */


#include "scc.h"

/*
 * Modifies:
 * id
 *
 * Effects:
 * Creates/refreshes the file cred cache id.  If the cache exists, its
 * contents ae destroyed.
 *
 * Errors:
 * system errors
 * permission errors
 */
krb5_error_code
krb5_scc_initialize(id, princ)
   krb5_ccache id;
   krb5_principal princ;
{
     int ret;

     ret = krb5_scc_open_file (id, SCC_OPEN_AND_ERASE);
     if (ret < 0)
	  return krb5_scc_interpret(errno);

#if 0
     ret = fchmod(((krb5_scc_data *) id->data)->fd, S_IREAD | S_IWRITE);
     if (ret == -1) {
	 ret = krb5_scc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     close(((krb5_scc_data *)id->data)->fd);
	     ((krb5_scc_data *) id->data)->fd = -1;
	 }
	 return ret;
     }
#endif
     krb5_scc_store_principal(id, princ);

     MAYBE_CLOSE (id, ret);
     return ret;
}


