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

#include <CoreServices/CoreServices.h>

#include "kim_os_private.h"

/* ------------------------------------------------------------------------ */
/* WARNING: DO NOT CALL check_error() -- it is called by error_message()!!  */

CFStringEncoding kim_os_string_get_encoding (void)
{
    typedef TextEncoding (*GetApplicationTextEncodingProcPtr) (void);
    GetApplicationTextEncodingProcPtr GetApplicationTextEncodingPtr = NULL;
    
    if (kim_os_library_caller_is_server ()) {
        return kCFStringEncodingUTF8;  /* server only does UTF8 */
    }
    
    CFBundleRef carbonBundle = CFBundleGetBundleWithIdentifier (CFSTR ("com.apple.Carbon"));
    if (carbonBundle != NULL && CFBundleIsExecutableLoaded (carbonBundle)) {
        GetApplicationTextEncodingPtr = (GetApplicationTextEncodingProcPtr) CFBundleGetFunctionPointerForName (carbonBundle,
                                                                                                               CFSTR ("GetApplicationTextEncoding"));
    }
    
    if (GetApplicationTextEncodingPtr) {
        return (CFStringEncoding) (*GetApplicationTextEncodingPtr) ();
    }
    
    return CFStringGetSystemEncoding ();
}

/* ------------------------------------------------------------------------ */
/* WARNING: DO NOT CALL check_error() -- it is called by error_message()!!  */

CFStringRef kim_os_string_get_cfstring_for_key_and_dictionary (CFStringRef in_key,
                                                               CFBundleRef in_bundle)
{
    CFDictionaryRef dictionary = NULL;
    CFStringRef value = NULL;
    
    if (kim_library_allow_home_directory_access ()) {
        // Accesses user's homedir to get localization information
        dictionary = CFBundleGetLocalInfoDictionary (in_bundle);
    } else {
        dictionary = CFBundleGetInfoDictionary (in_bundle);
    }
    
    if (dictionary) {
        value = (CFTypeRef) CFDictionaryGetValue (dictionary, in_key);
    }
    
    if (value && (CFGetTypeID (value) != CFStringGetTypeID ())) {
        value = NULL;  // Only return CFStrings
    }
    
    return value;    
}

/* ------------------------------------------------------------------------ */
/* WARNING: DO NOT CALL check_error() -- it is called by error_message()!!  */

CFStringRef kim_os_string_get_cfstring_for_key (kim_string in_key_string)
{
    CFStringRef key = NULL;
    CFStringRef value = NULL;
    
    if (in_key_string) {     
        key = CFStringCreateWithCString (kCFAllocatorDefault, in_key_string, kCFStringEncodingASCII);

        if (key) {
            // Try to find the key, first searching in the framework, then in the main bundle
            CFBundleRef frameworkBundle = CFBundleGetBundleWithIdentifier (CFSTR ("edu.mit.Kerberos"));
            if (frameworkBundle) {
                value = kim_os_string_get_cfstring_for_key_and_dictionary (key, frameworkBundle);
            }
            
            if (!value) {
                CFBundleRef mainBundle = CFBundleGetMainBundle ();

                if (mainBundle) {
                    value = kim_os_string_get_cfstring_for_key_and_dictionary (key, mainBundle);
                }
            }
            
            if (value && (CFGetTypeID (value) != CFStringGetTypeID ())) {
                value = NULL;  // Only return CFStrings
            }
            
            CFRelease (key);
        }
    }
    
    return value;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_os_string_create_from_cfstring (kim_string *out_string,
                                                CFStringRef in_cfstring)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    CFStringEncoding encoding = kim_os_string_get_encoding ();
    CFIndex length = 0;
    
    if (!err && !out_string ) { err = param_error (1, "out_string", "NULL"); }
    if (!err && !in_cfstring) { err = param_error (2, "in_cfstring", "NULL"); }
    
    if (!err) {
        length = CFStringGetMaximumSizeForEncoding (CFStringGetLength (in_cfstring), encoding) + 1;
        
        string = (char *) calloc (length, sizeof (char));
        if (!string) { err = os_error (errno); }
    }
    
    if (!err) {
        if (!CFStringGetCString (in_cfstring, (char *) string, length, encoding)) {
            err = os_error (ENOMEM);
        }        
    }
    
    if (!err) {
        *out_string = string;
        string = NULL;
    }
    
    kim_string_free (&string);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_string_create_for_key (kim_string *out_string,
                                          kim_string in_key_string)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef value = NULL;
    
    if (!err && !out_string   ) { err = param_error (1, "out_string", "NULL"); }
    if (!err && !in_key_string) { err = param_error (2, "in_key_string", "NULL"); }
    
    if (!err) {
        value = kim_os_string_get_cfstring_for_key (in_key_string);
        if (value) {
            err = kim_os_string_create_from_cfstring (out_string, value);
        } else {
            // We failed to look it up.   Use the key so we return something.
            err = kim_string_copy (out_string, in_key_string);
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_string_get_cfstring (kim_string  in_string,
                                        CFStringRef  *out_cfstring)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef cfstring = NULL;
    
    if (!err && !in_string   ) { err = param_error (1, "in_string", "NULL"); }
    if (!err && !out_cfstring) { err = param_error (2, "out_cfstring", "NULL"); }
    
    if (!err) {
        cfstring = CFStringCreateWithCString (kCFAllocatorDefault, in_string, kCFStringEncodingUTF8);
        if (!cfstring) { err = os_error (ENOMEM); }
    }
    
    if (!err) {
        *out_cfstring = cfstring;
        cfstring = NULL;
    }
    
    if (cfstring) { CFRelease (cfstring); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_string_compare (kim_string      in_string,
                                   kim_string      in_compare_to_string,
                                   kim_comparison *out_comparison)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef cfstring = NULL;
    CFStringRef compare_to_cfstring = NULL;
    
    if (!err && !in_string           ) { err = param_error (1, "in_string", "NULL"); }
    if (!err && !in_compare_to_string) { err = param_error (2, "in_compare_to_string", "NULL"); }
    if (!err && !out_comparison      ) { err = param_error (3, "out_comparison", "NULL"); }
    
    if (!err) {
        err = kim_os_string_get_cfstring (in_string, &cfstring);
    }

    if (!err) {
        err = kim_os_string_get_cfstring (in_compare_to_string, &compare_to_cfstring);
    }
    
    if (!err) {
        /* Returned CFComparisonResult is compatible with kim_comparison_t */
        *out_comparison = CFStringCompare (cfstring, compare_to_cfstring, 0);            
    }
    
    if (cfstring           ) { CFRelease (cfstring); }
    if (compare_to_cfstring) { CFRelease (compare_to_cfstring); }

    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_string_compare_to_cfstring (kim_string      in_string,
                                               CFStringRef       in_compare_to_cfstring,
                                               kim_comparison *out_comparison)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef cfstring = NULL;
    
    if (!err && !in_string             ) { err = param_error (1, "in_string", "NULL"); }
    if (!err && !in_compare_to_cfstring) { err = param_error (2, "in_compare_to_cfstring", "NULL"); }
    if (!err && !out_comparison        ) { err = param_error (3, "out_comparison", "NULL"); }
    
    if (!err) {
        err = kim_os_string_get_cfstring (in_string, &cfstring);
    }
    
    if (!err) {
        /* Returned CFComparisonResult is compatible with kim_comparison_t */
        *out_comparison = CFStringCompare (cfstring, in_compare_to_cfstring, 0);            
    }
    
    if (cfstring) { CFRelease (cfstring); }
    
    return check_error (err);    
}
