/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */
 
#include <Kerberos/com_err.h>

#include "KerberosProfileInit.h"
#include "profile.h"
#include "prof_err.h"

void KerberosProfileInit (CFStringRef inBundleID)
{
#if USE_HARDCODED_FALLBACK_ERROR_TABLES
	/* Initialize the error tables */
	add_error_table(&et_prof_error_table);
#endif
}
