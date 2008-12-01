/*
 * Copyright 2005-2006 Massachusetts Institute of Technology.
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

#ifndef KIM_H
#define KIM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <kim/kim_types.h>
#include <kim/kim_errors.h>
#include <kim/kim_string.h>
#include <kim/kim_identity.h>
#include <kim/kim_options.h>
#include <kim/kim_selection_hints.h>
#include <kim/kim_preferences.h>
#include <kim/kim_credential.h>
#include <kim/kim_ccache.h>

/*!
 * \mainpage Kerberos Identity Management (KIM) API Documentation
 *
 * \section introduction Introduction
 *
 * The Kerberos Identity Management API is a high level API for managing the selection 
 * and management of Kerberos credentials.  It is intended for use by applications,
 * credential management applications (eg: kinit, kpasswd, etc) and internally by the 
 * Kerberos libraries.  Under some circumstances client applications may also benefit 
 * from the Kerberos Identity Management API.
 *
 *
 * \section conventions API Conventions
 *
 * Although KIM currently only provides a C API, it attempts to make that API as 
 * object-oriented as possible.  KIM functions are grouped by object and all of the 
 * object types are opaque, including errors.  The reason for this is two-fold.  First,   
 * the KIM API is rather large.  Grouping functions by object allows the API to be  
 * broken up into smaller, more manageable chunks.  Second, providing an object-like C 
 * API will make it easier to port to object oriented languages.
 *
 * Because C lacks classes and other object oriented syntax, KIM functions adhere to 
 * the following naming conventions to make functions easier to identify:
 *
 * \li Functions beginning with \b kim_object_create are constructors for an object of
 * type kim_object.  On success these functions return a newly allocated object which
 * must later be freed by the caller.
 * 
 * \li Functions of the form \b kim_object_copy are copy constructors.  They instantiate
 * a new object of kim_object from an object of the same type.
 * 
 * \li Functions of the form \b kim_object_free are destructors for objects of type 
 * kim_object.  
 *
 * \li Functions beginning with \b kim_object_get and \b kim_object_set
 * examine and modify properties of objects of type kim_object.
 *
 * \li All KIM APIs except destructors and error management APIs return a 
 * KIM Error object (kim_error_t).  
 *
 *
 * \section terminology Terminology
 *
 * Kerberos organizes its authentication tokens by client identity (the name of the user)
 * and service identity (the name of a service).  The following terms are used throughout 
 * this documentation:
 *
 * \li <b>credential</b> - A token which authenticates a client identity to a 
 *                         service identity. 
 *
 * \li <b>ccache</b> - Short for "credentials cache".  A set of credentials for a single 
 *                     client identity.
 *
 * \li <b>cache collection</b> - The set of all credential caches.
 *
 * \li <b>default ccache</b> - A credentials cache that the Kerberos libraries will use  
 *                             if no ccache is specified by the caller.  Use of the default
 *                             ccache is now discouraged.  Instead applications should use 
 *                             selection hints to choose an appropriate client identity.
 *
 * \section selection_api Client Identity Selection APIs
 *
 * KIM provides high level APIs for applications to select which client identity to 
 * use.  Use of these APIs is intended to replace the traditional "default ccache" 
 * mechanism previously used by Kerberos.
 * 
 * <B>KIM Selection Hints (kim_selection_hints_t)</B> controls options for selecting 
 * a client identity:
 * - \subpage kim_selection_hints_overview
 * - \subpage kim_selection_hints_reference
 *
 * <B>KIM Identity (kim_identity_t)</B> provides an immutable Kerberos identity object
 * - \subpage kim_identity_overview
 * - \subpage kim_identity_reference
 *
 *
 * \section management_api Credential Management APIs
 *
 * KIM also provides APIs for acquiring new credentials over the network 
 * by contacting a KDC and for viewing and modifying the existing credentials
 * in the cache collection
 *
 * Whether or not you use the credential or ccache APIs depends on
 * whether you want KIM to store any newly acquired credentials in the
 * cache collection.  KIM ccache APIs always create a ccache in the cache 
 * collection containing newly acquired credentials whereas the KIM 
 * credential APIs just return a credential object.  In general most
 * callers want to store newly acquired credentials and should use the
 * KIM ccache APIs when acquiring credentials.
 *
 * <B>KIM CCache (kim_ccache_t)</B> manipulates credential caches in the cache collection:
 * - \subpage kim_ccache_overview
 * - \subpage kim_ccache_reference
 *
 * <B>KIM Credential (kim_credential_t)</B> manipulates credentials: 
 * - \subpage kim_credential_overview
 * - \subpage kim_credential_reference
 *
 * <B>KIM Options (kim_options_t)</B> control options for credential acquisition:
 * - \subpage kim_options_overview
 * - \subpage kim_options_reference
 * 
 * <B>KIM Preferences (kim_preferences_t)</B> views and edits the current user's preferences:
 * - \subpage kim_preferences_overview
 * - \subpage kim_preferences_reference
 *
 *
 * \section utility_apis Miscellaneous APIs
 *
 * The high and low level APIs depend on the following basic utility classes
 * to manage generic types.
 *
 * <B>KIM String (kim_string_t)</B> provides memory management for an immutable string:
 * - \subpage kim_string_overview
 * - \subpage kim_string_reference
 *
 *
 *
 * \section types Types and Constants
 *
 * \li \subpage kim_types_reference
 */

#ifdef __cplusplus
}
#endif

#endif /* KIM_H */
