/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_scc_set_flags.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_set_flags_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "scc.h"

/*
 * Requires:
 * id is a cred cache returned by krb5_scc_resolve or
 * krb5_scc_generate_new, but has not been opened by krb5_scc_initialize.
 *
 * Modifies:
 * id
 * 
 * Effects:
 * Sets the operational flags of id to flags.
 */
krb5_error_code
krb5_scc_set_flags(id, flags)
   krb5_ccache id;
   krb5_flags flags;
{
    krb5_error_code ret = 0;

    /* XXX This should check for illegal combinations, if any.. */
    if (flags & KRB5_TC_OPENCLOSE) {
	/* asking to turn on OPENCLOSE mode */
	if (!OPENCLOSE(id))
	    ret = krb5_scc_close_file (id);
    } else {
	/* asking to turn off OPENCLOSE mode, meaning it must be
	   left open.  We open if it's not yet open */
	if (OPENCLOSE(id)) {
	    ret = krb5_scc_open_file (id, "r+");
	}
    }

    ((krb5_scc_data *) id->data)->flags = flags;
    return ret;
}

