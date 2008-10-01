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

#ifndef KIM_TYPES_H
#define KIM_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \defgroup kim_types_reference KIM Types and Constants
 * @{
 */

/*!
 * The KIM Error type.
 */
typedef int32_t     kim_error;

/*!
 * No error value for the kim_error type.  
 */
#define KIM_NO_ERROR ((kim_error) 0)

/*!
 * A time value represented in seconds since January 1, 1970.
 */
typedef int64_t     kim_time;

/*!
 * A duration represented in seconds.
 */
typedef int64_t     kim_lifetime;

/*!
 * An quantity, usually used to return the number of elements in an array.
 */
typedef uint64_t    kim_count;

/*!
 * A boolean value.  0 means false, all other values mean true.
 */
typedef int         kim_boolean;

/*!
 * A comparison between two sortable objects.
 * \li Less than 0 means the first object is less than the second.
 * \li 0 means the two objects are identical.
 * \li Greater than 0 means the first object is greater than the second.
 * \note Convenience macros are provided for interpreting #kim_comparison
 * values to improve code readability.
 * See #kim_comparison_is_less_than(), #kim_comparison_is_equal_to() and 
 * #kim_comparison_is_greater_than()
 */
typedef int         kim_comparison;

/*!
 * Convenience macro for interpreting #kim_comparison.
 */
#define kim_comparison_is_less_than(c)    (c < 0)

/*!
 * Convenience macro for interpreting #kim_comparison.
 */
#define kim_comparison_is_equal_to(c)        (c == 0) 

/*!
 * Convenience macro for interpreting #kim_comparison.
 */
#define kim_comparison_is_greater_than(c) (c > 0)

/*!
 * The KIM String type.  See \ref kim_string_overview for more information.
 */
typedef const char *kim_string;

struct kim_identity_opaque;
/*!
 * A KIM Principal object.  See \ref kim_identity_overview for more information.
 */
typedef struct kim_identity_opaque *kim_identity;

struct kim_options_opaque;
/*!
 * A KIM Options object.  See \ref kim_options_overview for more information.
 */
typedef struct kim_options_opaque *kim_options;

struct kim_selection_hints_opaque;
/*!
 * A KIM Selection Hints object.  See \ref kim_selection_hints_overview for more information.
 */
typedef struct kim_selection_hints_opaque *kim_selection_hints;

struct kim_preferences_opaque;
/*!
 * A KIM Preferences object.  See \ref kim_preferences_overview for more information.
 */
typedef struct kim_preferences_opaque *kim_preferences;

struct kim_ccache_iterator_opaque;
/*!
 * A KIM CCache Iterator object.  See \ref kim_credential_cache_collection for more information.
 */
typedef struct kim_ccache_iterator_opaque *kim_ccache_iterator;

struct kim_ccache_opaque;
/*!
 * A KIM CCache object.  See \ref kim_ccache_overview for more information.
 */
typedef struct kim_ccache_opaque *kim_ccache;

struct kim_credential_iterator_opaque;
/*!
 * A KIM Credential Iterator object.  See \ref kim_credential_iterator for more information.
 */
typedef struct kim_credential_iterator_opaque *kim_credential_iterator;

struct kim_credential_opaque;
/*!
 * A KIM Credential object.  See \ref kim_credential_overview for more information.
 */
typedef struct kim_credential_opaque *kim_credential;

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_TYPES_H */
