/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_close.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_close_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "fcc.h"

/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the file cache, invalidates the id, and frees any resources
 * associated with the cache.
 */
krb5_error_code
krb5_fcc_close(id)
   krb5_ccache id;
{
     register int closeval = KRB5_OK;

     if (OPENCLOSE(id)) {
	 closeval = close(((krb5_fcc_data *) id->data)->fd);
	 ((krb5_fcc_data *) id->data)->fd = -1;
	 if (closeval == -1) {
	     closeval = krb5_fcc_interpret(errno);
	 } else
	     closeval = KRB5_OK;
		 
     }
     xfree(((krb5_fcc_data *) id->data)->filename);
     xfree(((krb5_fcc_data *) id->data));
     xfree(id);

     return closeval;
}
