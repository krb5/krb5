/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_scc_close.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_close_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "scc.h"

/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the file cache, invalidates the id, and frees any resources
 * associated with the cache.
 */
krb5_error_code
krb5_scc_close(id)
   krb5_ccache id;
{
     register int closeval = KRB5_OK;
     register krb5_scc_data *data = (krb5_scc_data *) id->data;

     if (!OPENCLOSE(id)) {
	 closeval = fclose (data->file);
	 data->file = 0;
	 if (closeval == -1) {
	     closeval = krb5_scc_interpret(errno);
	 } else
	     closeval = KRB5_OK;
		 
     }
     xfree (data->filename);
     xfree (data);
     xfree (id);

     return closeval;
}
