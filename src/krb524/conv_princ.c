/*
 * Copyright 1993 by Geer Zolot Associates.  All Rights Reserved.
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.  It
 * is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Geer Zolot Associates not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  Geer Zolot Associates makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 */

#include <stdio.h>
#include <krb5/krb5.h>
#include <krb.h>

#include "krb524.h"

int krb524_convert_princs(krb5_principal client, krb5_principal
			  server, char *pname, char *pinst, char
			  *prealm, char *sname, char *sinst)
{
     char dummy[REALM_SZ];
     int ret;
     
     if (ret = krb5_524_conv_principal(client, pname, pinst, prealm))
	  return ret;
     
     return krb5_524_conv_principal(server, sname, sinst, dummy);
}
