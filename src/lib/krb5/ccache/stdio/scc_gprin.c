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
 * This file contains the source code for krb5_scc_get_principal.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_gprinc_c[] =
"$Id$";
#endif /* !lint && !SABER */

#include "scc.h"

/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_scc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOMEM
 */
krb5_error_code
krb5_scc_get_principal(id, princ)
   krb5_ccache id;
   krb5_principal *princ;
{
     krb5_error_code kret;

     MAYBE_OPEN (id, SCC_OPEN_RDONLY);
     /* skip over vno at beginning of file */
     fseek(((krb5_scc_data *) id->data)->file, sizeof(krb5_int16), 0);

     kret = krb5_scc_read_principal(id, princ);

     MAYBE_CLOSE (id, kret);
     return kret;
}
