/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_copy_data()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_copy_data_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

/*
 * Copy a data structure, with fresh allocation.
 */
krb5_error_code
krb5_copy_data(indata, outdata)
const krb5_data *indata;
krb5_data **outdata;
{
    krb5_data *tempdata;

    if (!(tempdata = (krb5_data *)malloc(sizeof(*tempdata))))
	return ENOMEM;

    *tempdata = *indata;
    if (!(tempdata->data = malloc(tempdata->length))) {
	free((char *)tempdata);
	return ENOMEM;
    }
    memcpy((char *)tempdata->data, (char *)indata->data, tempdata->length);
    *outdata = tempdata;
    return 0;
}
