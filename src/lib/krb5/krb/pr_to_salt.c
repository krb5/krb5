/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_principal2salt()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_pr_to_salt_c[] =
"$Id$";
#endif  /* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

/*
 * Convert a krb5_principal into the default salt for that principal.
 */

krb5_error_code
krb5_principal2salt(pr, ret)
krb5_const_principal pr;
krb5_data *ret;
{
    int size, offset;
    krb5_data * const * prp;
    

    if (pr == 0) {
        ret->length = 0;
        ret->data = 0;
    } else {
        for (size = 0, prp = pr; *prp; prp++)
            size += (*prp)->length;

        ret->length = size;
        if (!(ret->data = malloc (size+1)))
	    return ENOMEM;

        for (offset=0, prp=pr; *prp; prp++)
        {
            memcpy(&ret->data[offset],(*prp)->data, (*prp)->length);
            offset += (*prp)->length;
        }
    }
    return 0;
}
