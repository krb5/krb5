/*
 * $Source$
 * $Author$
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_close.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_close_c[] =
"$Id$";
#endif /* !lint && !SABER */


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
