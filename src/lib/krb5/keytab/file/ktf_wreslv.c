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
 * This is an implementation specific resolver.  It returns a keytab id 
 * initialized with file keytab routines.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktfile_wresolve_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include "ktfile.h"

krb5_error_code
krb5_ktfile_wresolve(name, id)
  char *name;
  krb5_keytab *id;
{
    krb5_ktfile_data *data;

    if ((*id = (krb5_keytab) malloc(sizeof(**id))) == NULL)
	return(ENOMEM);
    
    (*id)->ops = &krb5_ktf_writable_ops;
    if ((data = (krb5_ktfile_data *)malloc(sizeof(krb5_ktfile_data))) == NULL) {
	xfree(*id);
	return(ENOMEM);
    }

    if ((data->name = (char *)calloc(strlen(name) + 1, sizeof(char))) == NULL) {
	xfree(data);
	xfree(*id);
	return(ENOMEM);
    }

    (void) strcpy(data->name, name);
    data->openf = 0;

    (*id)->data = (krb5_pointer)data;

    return(0);
}

