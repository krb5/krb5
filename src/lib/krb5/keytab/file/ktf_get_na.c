/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Get the name of the file containing a file-based keytab.
 */

#if !defined(lint) && !defined(SABER)
static char krb5_ktfile_get_name_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include "ktfile.h"

krb5_error_code
krb5_ktfile_get_name(id, name, len)
  krb5_keytab id;
  char *name;
  int len;
  /* 
   * This routine returns the name of the name of the file associated with
   * this file-based keytab.  name is zeroed and the filename is truncated
   * to fit in name if necessary.
   */
{
    bzero(name, len);
    strncpy(name, KTFILENAME(id), len);
    return(0); /* XXX */
}
