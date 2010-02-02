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
 * \section kim_string_error_messages KIM Error Messages
 *
 * Like most C APIs, the KIM API returns numeric error codes.  These error
 * codes may come from KIM, krb5 or GSS APIs.  In most cases the caller will
 * want to handle these error programmatically.  However, in some circumstances 
 * the caller may wish to print an error string to the user.  
 *
 * One problem with just printing the error code to the user is that frequently
 * the context behind the error has been lost.  For example if KIM is trying to 
 * obtain credentials via referrals, it may fail partway through the process.
 * In this case the error code will be KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, which
 * maps to "Client not found in Kerberos database".  Unfortunately this error
 * isn't terribly helpful because it doesn't tell the user whether they typoed
 * their principal name or if referrals failed.  
 *
 * To avoid this problem, KIM maintains an explanatory string for the last 
 * error seen in each thread calling into KIM.  If a caller wishes to display
 * an error to the user, immediately after getting the error the caller should
 * call #kim_string_create_for_last_error() to obtain a copy of the  
 * descriptive error message.
 *
 * See \ref kim_string_reference for information on specific APIs.
 */

/*!
 * \defgroup kim_string_reference KIM String Reference Documentation
 * @{
 */

/*!
 * \param out_string On success, a human-readable UTF-8 string describing the 
 *                   error representedby \a in_error.  Must be freed with
 *                   kim_string_free().
 * \param in_error   an error code.  Used to verify that the correct error
 *                   string will be returned (see note below).
 * \return On success, KIM_NO_ERROR.  
 * \note This API is implemented using thread local storage.  It should be 
 * called immediately after a KIM API returns an error code so that the correct
 * string is returned.  The returned copy may then be held by the caller until 
 * needed.  If \a in_error does not match the last saved error KIM may return
 * a less descriptive string.
 * \brief Get a text description of an error suitable for display to the user.
 */
kim_error kim_string_create_for_last_error (kim_string *out_string,
                                            kim_error   in_error);
    
/*!
 * \param out_string on exit, a new string object which is a copy of \a in_string.  
                     Must be freed with kim_string_free().
 * \param in_string  the string to copy.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Copy a string.
 */
kim_error kim_string_copy (kim_string       *out_string,
                           const kim_string  in_string);

/*!
 * \param in_string            a string.
 * \param in_compare_to_string a string to be compared to \a in_string.
 * \param out_comparison       on exit, a comparison result indicating whether \a in_string
 *                             is greater than, less than or equal to \a in_compare_to_string.
 * \return On success, #KIM_NO_ERROR.  On failure, an error code representing the failure.
 * \brief Compare two strings.
 */
kim_error kim_string_compare (kim_string      in_string, 
                              kim_string      in_compare_to_string,
                              kim_comparison *out_comparison);
    
/*!
 * \param io_string a string to be freed.  Set to NULL on exit.
 * \brief Free memory associated with a string.
 */
void kim_string_free (kim_string *io_string);

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_STRING_H */
