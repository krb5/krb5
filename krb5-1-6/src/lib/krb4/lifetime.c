/*
 * Copyright 2000, 2001, 2003 by the Massachusetts Institute of Technology.
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

#include "krb.h"
#include "k5-int.h"

/*
 * krb_life_to_time
 *
 * Given a start date and a lifetime byte, compute the expiration
 * date.
 */
KRB4_32 KRB5_CALLCONV
krb_life_to_time(KRB4_32 start, int life)
{
    krb5int_access k5internals;

    if (krb5int_accessor(&k5internals, KRB5INT_ACCESS_VERSION)
	|| k5internals.krb_life_to_time == NULL)
	return start;
    return k5internals.krb_life_to_time(start, life);
}

/*
 * krb_time_to_life
 *
 * Given the start date and the end date, compute the lifetime byte.
 * Round up, since we can adjust the start date backwards if we are
 * issuing the ticket to cause it to expire at the correct time.
 */
int KRB5_CALLCONV
krb_time_to_life(KRB4_32 start, KRB4_32 end)
{
    krb5int_access k5internals;

    if (krb5int_accessor(&k5internals, KRB5INT_ACCESS_VERSION)
	|| k5internals.krb_time_to_life == NULL)
	return 0;
    return k5internals.krb_time_to_life(start, end);
}
