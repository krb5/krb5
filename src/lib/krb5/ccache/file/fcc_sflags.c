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
 * This file contains the source code for krb5_fcc_set_flags.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_set_flags_c[] =
"$Id$";
#endif /* !lint && !SABER */


#include "fcc.h"

/*
 * Requires:
 * id is a cred cache returned by krb5_fcc_resolve or
 * krb5_fcc_generate_new, but has not been opened by krb5_fcc_initialize.
 *
 * Modifies:
 * id
 * 
 * Effects:
 * Sets the operational flags of id to flags.
 */
krb5_error_code
krb5_fcc_set_flags(id, flags)
   krb5_ccache id;
   krb5_flags flags;
{
    /* XXX This should check for illegal combinations, if any.. */
    if (flags & KRB5_TC_OPENCLOSE) {
	/* asking to turn on OPENCLOSE mode */
	if (!OPENCLOSE(id)) {
	    (void) krb5_fcc_close_file (id);
	}
    } else {
	/* asking to turn off OPENCLOSE mode, meaning it must be
	   left open.  We open if it's not yet open */
	MAYBE_OPEN(id, FCC_OPEN_RDONLY);
    }

    ((krb5_fcc_data *) id->data)->flags = flags;
    return KRB5_OK;
}

