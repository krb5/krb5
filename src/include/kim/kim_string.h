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

#ifndef KIM_STRING_H
#define KIM_STRING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <kim/kim_types.h>

/*!
 * \page kim_string_overview KIM String Overview
 *
 * A UTF8 string.  
 * 
 * Memory management routines are provided for runtime consistency on
 * operating systems with shared libraries and multiple runtimes.
 *
 * See \ref kim_string_reference for information on specific APIs.
 */

/*!
 * \defgroup kim_string_reference KIM String Reference Documentation
 * @{
 */

/*!
 * \param out_string on exit, a new string object which is a copy of \a in_string.  
                     Must be freed with kim_string_free().
 * \param in_string  the string to copy.
 * \return On success, #KIM_NO_ERROR.  On failure, an error object representing the failure.
 * \brief Copy a string.
 */
kim_error_t kim_string_copy (kim_string_t       *out_string,
                             const kim_string_t  in_string);

/*!
 * \param in_string            a string.
 * \param in_compare_to_string a string to be compared to \a in_string.
 * \param out_comparison       on exit, a comparison result indicating whether \a in_string
 *                             is greater than, less than or equal to \a in_compare_to_string.
 * \return On success, #KIM_NO_ERROR.  On failure, an error object representing the failure.
 * \brief Compare two strings.
 */
kim_error_t kim_string_compare (kim_string_t      in_string, 
                                kim_string_t      in_compare_to_string,
                                kim_comparison_t *out_comparison);
    
/*!
 * \param io_string a string to be freed.  Set to NULL on exit.
 * \brief Free memory associated with a string.
 */
void kim_string_free (kim_string_t *io_string);

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_STRING_H */
