/*
 * lib/krb5/ccache/file/fcc_init.c
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
 * This file contains the source code for krb5_fcc_initialize.
 */


#include <errno.h>
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

#ifdef NOFCHMOD
     ret = chmod(((krb5_fcc_data *) id->data)->filename, S_IREAD | S_IWRITE);
#else
     ret = fchmod(((krb5_fcc_data *) id->data)->fd, S_IREAD | S_IWRITE);
#endif
     if (ret == -1) {
	 ret = krb5_fcc_interpret(errno);
	 MAYBE_CLOSE(id, ret);
	 return ret;
     }
     krb5_fcc_store_principal(id, princ);

     MAYBE_CLOSE(id, ret);
     return ret;
}


