/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for reading variables from a
 * credentials cache.  These are not library-exported functions.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_read_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>
#include "scc.h"

krb5_error_code
krb5_scc_skip_principal(id)
   krb5_ccache id;
{
     krb5_error_code kret;
     krb5_principal princ;

     kret = krb5_scc_read_principal(id, &princ);
     if (kret != KRB5_OK)
	  return kret;

     /* XXX krb5_destroy_principal(&princ); */
     return KRB5_OK;
}

     
