/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_set_flags.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_set_flags_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

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
    krb5_error_code ret;

    /* XXX This should check for illegal combinations, if any.. */
    if (flags & KRB5_TC_OPENCLOSE) {
	/* asking to turn on OPENCLOSE mode */
	if (!OPENCLOSE(id)) {
	    (void) close(((krb5_fcc_data *) id->data)->fd);
	    ((krb5_fcc_data *) id->data)->fd = -1;
	}
    } else {
	/* asking to turn off OPENCLOSE mode, meaning it must be
	   left open.  We open if it's not yet open */
	if (OPENCLOSE(id)) {
	    ret = open(((krb5_fcc_data *) id->data)->filename, O_RDONLY, 0);
	    if (ret < 0)
		return errno;
	    ((krb5_fcc_data *) id->data)->fd = ret;
	}
    }

    ((krb5_fcc_data *) id->data)->flags = flags;
    return KRB5_OK;
}

