/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * "Close" a file-based keytab and invalidate the id.  This means
 * free memory hidden in the structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_krb5_ktfile_close_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "ktfile.h"

krb5_error_code 
krb5_ktfile_close(id)
  krb5_keytab id;
  /*
   * This routine is responsible for freeing all memory allocated 
   * for this keytab.  There are no system resources that need
   * to be freed nor are there any open files.
   *
   * This routine should undo anything done by krb5_ktfile_resolve().
   */
{
    xfree(KTFILENAME(id));
    xfree(id->data);
    id->ops = 0;
    xfree(id);
    return (0);
}
