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
 * dummy function for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_des_sched_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"

/*
 * This is a no-op because V5 will always creates it when needed.
 */
int
des_key_sched(k, s)
des_cblock k;
des_key_schedule s;
{
	/*
	 * Use the variables so saber does not get mad...
	 */
	if (k || s)
		return(0);
	return(0);
}
