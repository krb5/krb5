/*
 * lib/krb4/strnlen.c
 *
 * Copyright 2000, 2001 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 */

#include <stddef.h>
#include "krb.h"
#include "prot.h"

/*
 * krb4int_strnlen()
 *
 * Return the length of the string if a NUL is found in the first n
 * bytes, otherwise, -1.
 */

int KRB5_CALLCONV
krb4int_strnlen(const char *s, int n)
{
    int i = 0;

    for (i = 0; i < n; i++) {
        if (s[i] == '\0') {
            return i;
	}
    }
    return -1;
}
