/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_free_padata()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_padata_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_pa_data(val)
krb5_pa_data **val;
{
    register krb5_pa_data **temp;

    for (temp = val; *temp; temp++) {
	if ((*temp)->contents)
	    xfree((*temp)->contents);
	xfree(*temp);
    }
    xfree(val);
    return;
}
