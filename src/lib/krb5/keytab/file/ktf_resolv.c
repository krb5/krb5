/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This is an implementation specific resolver.  It returns a keytab id 
 * initialized with file keytab routines.
 */

#if !defined(lint) && !defined(SABER)
static char krb5_ktfile_resolve_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>

#include "ktfile.h"

krb5_error_code
krb5_ktfile_resolve(name, id)
  char *name;
  krb5_keytab *id;
{
    krb5_ktfile_data *data;

    if ((*id = malloc(sizeof(struct _krb5_kt))) == NULL)
	return(KRB5_NO_MEMORY); /* XXX */
    
    (*id)->ops = &krb5_ktf_ops;
    if ((data = (krb5_ktfile_data *)malloc(sizeof(krb5_ktfile_data))) == NULL)
	return(KRB5_NO_MEMORY); /* XXX */

    if ((data->name = (char *)calloc(strlen(name) + 1, sizeof(char))) == NULL)
	return(KRB5_NO_MEMORY); /* XXX */

    (void) strcpy(data->name, name);

    id->data = (krb5_pointer)data;

    return(0); /* XXX */
}

