/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Dump out a krb5_data to stderr (for debugging purposes).
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_dump_c[] =
"$Id$";
#endif	/* !lint & !SABER */


#include <stdio.h>

#include <krb5/krb5.h>

void dump_data (data)
    krb5_data *data;
{
    unsigned char *ptr = (unsigned char *)data->data;
    int i;
    for (i=0; i<data->length; i++) {
	fprintf(stderr, "%02x ", ptr[i]);
	if ((i % 16) == 15) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");    
}
