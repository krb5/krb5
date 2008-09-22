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

#include "kim_os_private.h"

/* ------------------------------------------------------------------------ */
static kim_error kim_os_string_for_key_in_bundle (CFBundleRef  in_bundle, 
                                                  CFStringRef  in_key,
                                                  kim_string  *out_string)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    
    if (!err && !in_bundle ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_key    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        CFDictionaryRef dictionary = NULL;
        int release_dictionary = 0;
        CFStringRef cfstring = NULL;
        
#if !KERBEROS_LITE
        if (kim_library_allow_home_directory_access ()) {
#endif
            /* Accesses user's homedir to get localization information */
            dictionary = CFBundleGetLocalInfoDictionary (in_bundle);
            
#if !KERBEROS_LITE
        } else {
            CFURLRef url = NULL;
            CFDataRef data = NULL;
            CFAllocatorRef allocator = CFGetAllocator (in_bundle);
            SInt32 code = 0;
            
            url = CFBundleCopyResourceURLForLocalization (in_bundle,
                                                          CFSTR("InfoPlist"),
                                                          CFSTR("strings"),
                                                          NULL,
                                                          CFSTR("English"));
            
            if (url && CFURLCreateDataAndPropertiesFromResource (allocator, 
                                                                 url, &data, 
                                                                 NULL, NULL, 
                                                                 &code)) {
                
                dictionary = CFPropertyListCreateFromXMLData (allocator, 
                                                              data, 
                                                              kCFPropertyListImmutable, 
                                                              NULL);
                release_dictionary = 1;
            }
            
            if (data) { CFRelease (data); }
            if (url ) { CFRelease (url); }
        }
#endif
        
        if (dictionary && (CFGetTypeID(dictionary) == CFDictionaryGetTypeID())) {
            cfstring = (CFStringRef) CFDictionaryGetValue (dictionary, in_key);
        }
        
        if (cfstring && (CFGetTypeID (cfstring) == CFStringGetTypeID ())) {
            err = kim_os_string_create_from_cfstring (&string, cfstring);
        }
        
        if (dictionary && release_dictionary) { CFRelease (dictionary); }
    }
    
    if (!err) {
        /* set to NULL if no string found */
        *out_string = string;
        string = NULL;
    }
    
    kim_string_free (&string);
    
    return check_error (err);
}

#pragma mark -

/* ------------------------------------------------------------------------ */

kim_error kim_os_string_create_localized (kim_string *out_string,
                                          kim_string in_string)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    
    if (!err && !out_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_string ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
   
    if (!err) {
        err = kim_os_string_create_for_key (&string, in_string);
    }
    
    if (!err && !string) {
        err = kim_string_copy (&string, in_string);
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
    kim_error lock_err = kim_os_library_lock_for_bundle_lookup ();
    kim_error err = lock_err;
    CFStringRef key = NULL;
    kim_string string = NULL;
    
    if (!err && !out_string   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_key_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_os_string_get_cfstring (in_key_string, &key);
    }
    
    if (!err) {
        /* Try to find the key, first searching in the framework */
        CFBundleRef framework = CFBundleGetBundleWithIdentifier (CFSTR ("edu.mit.Kerberos"));
        if (framework) {
            err = kim_os_string_for_key_in_bundle (framework, key, &string);
        }
    }
    
    if (!err && !string) {
        /* If we didn't find it in the framwork, try in the main bundle */
        CFBundleRef main_bundle = CFBundleGetMainBundle ();
        if (main_bundle) {
            err = kim_os_string_for_key_in_bundle (main_bundle, key, &string);
        }
    }
    
    if (!err) {
        *out_string = string;
        string = NULL;
    }
    
    kim_string_free (&string);
    if (key) { CFRelease (key); }
    
    if (!lock_err) { kim_os_library_unlock_for_bundle_lookup (); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_string_create_from_cfstring (kim_string  *out_string,
                                              CFStringRef  in_cfstring)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    CFIndex length = 0;
    
    if (!err && !out_string ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_cfstring) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        length = CFStringGetMaximumSizeForEncoding (CFStringGetLength (in_cfstring), 
                                                    kCFStringEncodingUTF8) + 1;
        
        string = (char *) calloc (length, sizeof (char));
        if (!string) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        if (!CFStringGetCString (in_cfstring, 
                                 (char *) string, 
                                 length, 
                                 kCFStringEncodingUTF8)) {
            err = KIM_OUT_OF_MEMORY_ERR;
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

kim_error kim_os_string_get_cfstring (kim_string   in_string,
                                      CFStringRef *out_cfstring)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef cfstring = NULL;
    
    if (!err && !in_string   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_cfstring) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        cfstring = CFStringCreateWithCString (kCFAllocatorDefault, 
                                              in_string, 
                                              kCFStringEncodingUTF8);
        if (!cfstring) { err = KIM_OUT_OF_MEMORY_ERR; }
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
                                 kim_boolean     in_case_insensitive,
                                 kim_comparison *out_comparison)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef cfstring = NULL;
    CFStringRef compare_to_cfstring = NULL;
    
    if (!err && !in_string           ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_compare_to_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_comparison      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_os_string_get_cfstring (in_string, 
                                          &cfstring);
    }
    
    if (!err) {
        err = kim_os_string_get_cfstring (in_compare_to_string, 
                                          &compare_to_cfstring);
    }
    
    if (!err) {
        CFOptionFlags options = (in_case_insensitive ? 
                                 1 : kCFCompareCaseInsensitive);
        
        /* Returned CFComparisonResult is compatible with kim_comparison_t */
        *out_comparison = CFStringCompare (cfstring, 
                                           compare_to_cfstring, 
                                           options);            
    }
    
    if (cfstring           ) { CFRelease (cfstring); }
    if (compare_to_cfstring) { CFRelease (compare_to_cfstring); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_os_string_compare_to_cfstring (kim_string      in_string,
                                             CFStringRef     in_compare_to_cfstring,
                                             kim_comparison *out_comparison)
{
    kim_error err = KIM_NO_ERROR;
    CFStringRef cfstring = NULL;
    
    if (!err && !in_string             ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_compare_to_cfstring) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_comparison        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
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
