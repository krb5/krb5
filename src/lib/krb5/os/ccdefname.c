/*
 * lib/krb5/os/ccdefname.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * Return default cred. cache name.
 */

#include "k5-int.h"
#include <stdio.h>

char *krb5_cc_default_name(context)
    krb5_context context;
{
    char *name = getenv(KRB5_ENV_CCNAME);
    static char *name_buf;
    
    if (name == 0) {
	if (name_buf == 0)
	    name_buf = malloc (35);
	
	sprintf(name_buf, "FILE:/tmp/krb5cc_%d", getuid());
	name = name_buf;
    }
    return name;
}
    
