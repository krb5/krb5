/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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
 */

#include <CoreFoundation/CoreFoundation.h>
#include "k5-int.h"
#include "k5-thread.h"
#include <krb5/krb5.h>

#include "kim_os_private.h"


static k5_mutex_t g_bundle_lookup_mutex = K5_MUTEX_PARTIAL_INITIALIZER;

MAKE_INIT_FUNCTION(kim_os_library_thread_init);
MAKE_FINI_FUNCTION(kim_os_library_thread_fini);

/* ------------------------------------------------------------------------ */

static int kim_os_library_thread_init (void)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err) {
        err = k5_mutex_finish_init (&g_bundle_lookup_mutex);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static void kim_os_library_thread_fini (void)
{
    if (!INITIALIZER_RAN (kim_os_library_thread_init) || PROGRAM_EXITING ()) {
	return;
    }
    k5_mutex_destroy (&g_bundle_lookup_mutex);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_os_library_lock_for_bundle_lookup (void)
{
    kim_error err = CALL_INIT_FUNCTION (kim_os_library_thread_init);
    
    if (!err) {
        err = k5_mutex_lock (&g_bundle_lookup_mutex);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_library_unlock_for_bundle_lookup (void)
{
    kim_error err = CALL_INIT_FUNCTION (kim_os_library_thread_init);
    
    if (!err) {
        err = k5_mutex_unlock (&g_bundle_lookup_mutex);
    }
    
    return err;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_boolean kim_os_library_caller_is_server (void)
{
    CFBundleRef mainBundle = CFBundleGetMainBundle ();
    if (mainBundle) {
        CFStringRef mainBundleID = CFBundleGetIdentifier (mainBundle);
        if (mainBundleID) {
            CFComparisonResult result;
            result = CFStringCompare (mainBundleID, CFSTR("edu.mit.Kerberos.KerberosAgent"), 0);
            if (result == kCFCompareEqualTo) {
                return TRUE;
            }
        }
    }
    
    return FALSE;
}
