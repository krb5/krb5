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
 * Initialize Kerberos library error tables.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_init_ets_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>

void
krb5_init_ets PROTOTYPE((void))
{
    initialize_krb5_error_table();
    initialize_kdb5_error_table();
    initialize_isod_error_table();
}
