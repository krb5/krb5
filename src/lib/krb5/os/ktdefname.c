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
 * Return default keytab file name.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktdefname_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/osconf.h>

#include <krb5/ext-proto.h>

extern char *krb5_defkeyname;

krb5_error_code
krb5_kt_default_name(name, namesize)
char *name;
int namesize;
{
    strncpy(name, krb5_defkeyname, namesize);
    if (namesize < strlen(krb5_defkeyname))
	return KRB5_CONFIG_NOTENUFSPACE;
    else
	return 0;
}
    
