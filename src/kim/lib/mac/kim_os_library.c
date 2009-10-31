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
#include <Security/AuthSession.h>
#include <mach-o/dyld.h>
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

kim_boolean kim_os_library_caller_uses_gui (void)
{
    kim_boolean caller_uses_gui = 0;

    /* Check for the HIToolbox (Carbon) or AppKit (Cocoa).
     * If either is loaded, we are a GUI app! */
    CFBundleRef appKitBundle = CFBundleGetBundleWithIdentifier (CFSTR ("com.apple.AppKit"));
    CFBundleRef hiToolBoxBundle = CFBundleGetBundleWithIdentifier (CFSTR ("com.apple.HIToolbox"));

    if (hiToolBoxBundle && CFBundleIsExecutableLoaded (hiToolBoxBundle)) {
        caller_uses_gui = 1; /* Using Carbon */
    }

    if (appKitBundle && CFBundleIsExecutableLoaded (appKitBundle)) {
        caller_uses_gui = 1; /* Using Cocoa */
    }

    return caller_uses_gui;
}

/* ------------------------------------------------------------------------ */

kim_ui_environment kim_os_library_get_ui_environment (void)
{
#ifdef KIM_BUILTIN_UI
    kim_boolean has_gui_access = 0;
    SessionAttributeBits sattrs = 0L;

    has_gui_access = ((SessionGetInfo (callerSecuritySession,
                                       NULL, &sattrs) == noErr) &&
                      (sattrs & sessionHasGraphicAccess));

    if (has_gui_access && kim_os_library_caller_uses_gui ()) {
        return KIM_UI_ENVIRONMENT_GUI;
    }

    {
        int fd_stdin = fileno (stdin);
        int fd_stdout = fileno (stdout);
        char *fd_stdin_name = ttyname (fd_stdin);

        /* Session info isn't reliable for remote sessions.
         * Check manually for terminal access with file descriptors */
        if (isatty (fd_stdin) && isatty (fd_stdout) && fd_stdin_name) {
            return KIM_UI_ENVIRONMENT_CLI;
        }
    }

    /* If we don't have a CLI but can talk to the GUI, use that */
    if (has_gui_access) {
        return KIM_UI_ENVIRONMENT_GUI;
    }

    kim_debug_printf ("kim_os_library_get_ui_environment(): no way to talk to the user.");
#endif
    return KIM_UI_ENVIRONMENT_NONE;
}

/* ------------------------------------------------------------------------ */

kim_boolean kim_os_library_caller_is_server (void)
{
    CFBundleRef mainBundle = CFBundleGetMainBundle ();
    if (mainBundle) {
        CFStringRef mainBundleID = CFBundleGetIdentifier (mainBundle);
        if (mainBundleID) {
            CFComparisonResult result;
            result = CFStringCompare (mainBundleID, CFSTR(kim_os_agent_bundle_id), 0);
            if (result == kCFCompareEqualTo) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_os_library_get_application_path (kim_string *out_path)
{
    kim_error err = KIM_NO_ERROR;
    kim_string path = NULL;
    CFBundleRef bundle = CFBundleGetMainBundle ();

    if (!err && !out_path) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    /* Check if the caller is a bundle */
    if (!err && bundle) {
        CFURLRef bundle_url = CFBundleCopyBundleURL (bundle);
        CFURLRef resources_url = CFBundleCopyResourcesDirectoryURL (bundle);
        CFURLRef executable_url = CFBundleCopyExecutableURL (bundle);
        CFURLRef absolute_url = NULL;
        CFStringRef cfpath = NULL;

        if (bundle_url && resources_url && !CFEqual (bundle_url, resources_url)) {
            absolute_url = CFURLCopyAbsoluteURL (bundle_url);
        } else if (executable_url) {
            absolute_url = CFURLCopyAbsoluteURL (executable_url);
        }

        if (absolute_url) {
            cfpath = CFURLCopyFileSystemPath (absolute_url,
                                              kCFURLPOSIXPathStyle);
            if (!cfpath) { err = check_error (KIM_OUT_OF_MEMORY_ERR); }
        }

        if (!err && cfpath) {
            err = kim_os_string_create_from_cfstring (&path, cfpath);
        }

        if (cfpath        ) { CFRelease (cfpath); }
        if (absolute_url  ) { CFRelease (absolute_url); }
        if (bundle_url    ) { CFRelease (bundle_url); }
        if (resources_url ) { CFRelease (resources_url); }
        if (executable_url) { CFRelease (executable_url); }
    }

    /* Caller is not a bundle, try _NSGetExecutablePath */
    /* Note: this does not work on CFM applications */
    if (!err && !path) {
        char *buffer = NULL;
        uint32_t len = 0;

        /* Tiny stupid buffer to get the length of the path */
        if (!err) {
            buffer = malloc (1);
            if (!buffer) { err = check_error (KIM_OUT_OF_MEMORY_ERR); }
        }

        /* Get the length of the path */
        if (!err) {
            if (_NSGetExecutablePath (buffer, &len) != 0) {
                char *temp = realloc (buffer, len + 1);
                if (!temp) {
                    err = check_error (KIM_OUT_OF_MEMORY_ERR);
                } else {
                    buffer = temp;
                }
            }
        }

        /* Get the path */
        if (!err) {
            if (_NSGetExecutablePath (buffer, &len) != 0) {
                err = check_error (KIM_OUT_OF_MEMORY_ERR);
            } else {
                err = kim_string_copy (&path, buffer);
            }
        }

        if (buffer) { free (buffer); }
    }

    if (!err) {
        *out_path = path;
        path = NULL;
    }

    kim_string_free (&path);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_library_get_caller_name (kim_string *out_application_name)
{
    kim_error err = KIM_NO_ERROR;
    kim_string name = NULL;
    CFBundleRef bundle = CFBundleGetMainBundle ();
    CFStringRef cfname = NULL;

    if (!err && !out_application_name) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err && bundle) {
        cfname = CFBundleGetValueForInfoDictionaryKey (bundle,
                                                       kCFBundleNameKey);

        if (!cfname || CFGetTypeID (cfname) != CFStringGetTypeID ()) {
            cfname = CFBundleGetValueForInfoDictionaryKey (bundle,
                                                           kCFBundleExecutableKey);
        }

        if (cfname) {
            cfname = CFStringCreateCopy (kCFAllocatorDefault, cfname);
        }
    }

    if (!err && !cfname) {
        kim_string path = NULL;
        CFURLRef cfpath = NULL;
        CFURLRef cfpathnoext = NULL;

        err = kim_os_library_get_application_path (&path);

        if (!err) {
            cfpath = CFURLCreateFromFileSystemRepresentation (kCFAllocatorDefault,
                                                              (const UInt8 *) path,
                                                              strlen (path),
                                                              0);

            if (cfpath) {
                cfpathnoext = CFURLCreateCopyDeletingPathExtension (kCFAllocatorDefault,
                                                                    cfpath);
            }

            if (cfpathnoext) {
                cfname = CFURLCopyLastPathComponent (cfpathnoext);
            } else {
                cfname = CFURLCopyLastPathComponent (cfpath);
            }
        }

        if (cfpathnoext) { CFRelease (cfpathnoext); }
        if (cfpath     ) { CFRelease (cfpath); }
        kim_string_free (&path);
    }

    if (!err && cfname) {
        err = kim_os_string_create_from_cfstring (&name, cfname);
    }

    if (!err) {
        *out_application_name = name;
        name = NULL;

    }

    if (cfname) { CFRelease (cfname); }
    kim_string_free (&name);

    return check_error (err);
}
