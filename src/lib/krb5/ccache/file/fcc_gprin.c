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
 * This file contains the source code for krb5_fcc_get_principal.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_gprinc_c[] =
"$Id$";
#endif /* !lint && !SABER */

#include "fcc.h"

/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_fcc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOMEM
 */
krb5_error_code
krb5_fcc_get_principal(id, princ)
   krb5_ccache id;
   krb5_principal *princ;
{
     krb5_error_code kret = KRB5_OK;

     MAYBE_OPEN(id, FCC_OPEN_RDONLY);
     /* make sure we're beyond the vno */
     lseek(((krb5_fcc_data *) id->data)->fd, sizeof(krb5_int16), L_SET);

     kret = krb5_fcc_read_principal(id, princ);

     MAYBE_CLOSE(id, kret);
     return kret;
}

     
