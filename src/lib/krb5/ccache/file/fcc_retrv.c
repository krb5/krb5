/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_retrieve.
 */

#ifndef	lint
static char fcc_retrieve_c[] = "$Id$";
#endif	/* lint */

#include <krb5/copyright.h>

#include "fcc.h"

/*
 * Effects:
 * Searches the file cred cache is for a credential matching mcreds.
 * If one if found, it is returned in creds, which should be freed by
 * the caller with krb5_free_credentials().
 *
 * Errors:
 * system errors
 * permission errors
 * KRB5_NOMEM
 */
krb5_error_code
krb5_fcc_retrieve(id, whichfields, mcreds, creds)
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
     /* Just a wrapper for the sequential search routines */
}
