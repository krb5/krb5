/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * "Close" a file-based keytab and invalidate the id.  This means
 * free memory hidden in the structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_krb5_ktfile_close_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include <stdio.h>
#include <stdlib.h>

#include "ktfile.h"

krb5_error_code 
krb5_ktfile_close(id)
  krb5_keytab *id;
  /*
   * This routine is responsible for freeing all memory allocated 
   * for this keytab.  There are no system resources that need
   * to be freed nor are there any open files.
   *
   * This routine should undo anything done by krb5_ktfile_resolve().
   */
{
    (void) free(KTFILENAME(*id));
    (void) free((krb5_pointer)(*id)->data);
    *id = NULL;
    return (0); /* XXX */
}
