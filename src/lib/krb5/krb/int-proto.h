/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990,1991 the Massachusetts Institute of Technology.
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
 * Function prototypes for Kerberos V5 library internal functions.
 */


#ifndef KRB5_INT_FUNC_PROTO__
#define KRB5_INT_FUNC_PROTO__
/* widen prototypes, if needed */
#include <krb5/widen.h>

krb5_error_code krb5_tgtname
    PROTOTYPE((const krb5_data *,
	       const krb5_data *,
	       krb5_principal *));
krb5_error_code krb5_get_cred_via_tgt
    PROTOTYPE((krb5_creds *,
	       const krb5_flags,
	       const krb5_enctype,
	       const krb5_cksumtype,
	       krb5_creds * ));
/* and back to normal... */
#include <krb5/narrow.h>

#endif /* KRB5_INT_FUNC_PROTO__ */

