/*
 * lib/krb5/error_tables/init_ets.c
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
 * Initialize Kerberos library error tables.
 */

#include "k5-int.h"

static int et_init = 0;

void
krb5_init_ets (context)
     krb5_context context;
{
    initialize_krb5_error_table();
    initialize_kv5m_error_table();
    initialize_kdb5_error_table();
    initialize_asn1_error_table();
}

void
krb5_free_ets (context)
    krb5_context context;
{
}
