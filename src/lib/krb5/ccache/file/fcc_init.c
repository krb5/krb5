/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_initialize.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_init_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "fcc.h"

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
krb5_fcc_initialize(id, princ)
   krb5_ccache id;
   krb5_principal princ;
{
     int ret = KRB5_OK;

     MAYBE_OPEN(id, FCC_OPEN_AND_ERASE);

     ret = fchmod(((krb5_fcc_data *) id->data)->fd, S_IREAD | S_IWRITE);
     if (ret == -1) {
	 ret = krb5_fcc_interpret(errno);
	 MAYBE_CLOSE(id, ret);
	 return ret;
     }
     krb5_fcc_store_principal(id, princ);

     MAYBE_CLOSE(id, ret);
     return ret;
}


