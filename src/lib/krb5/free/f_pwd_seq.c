/*
 * lib/krb5/free/f_pwd_seq.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * krb5_free_pwd_sequences()
 */

#include "k5-int.h"

KRB5_DLLIMP void KRB5_CALLCONV
krb5_free_pwd_sequences(context, val)
    krb5_context context;
    passwd_phrase_element FAR * FAR *val;
{
    if ((*val)->passwd)
	krb5_xfree((*val)->passwd);
    if ((*val)->phrase)
	krb5_xfree((*val)->phrase);
    return;
}
