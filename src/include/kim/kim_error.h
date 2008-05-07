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

#ifndef KIM_ERROR_H
#define KIM_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <kim/kim_types.h>
#include <kim/kim_error_code.h>

/*!
 * \ingroup kim_types_reference
 * The kim_error_t returned when no error occurred. 
 * Does not need to be freed with kim_error_free().
 */
#define KIM_NO_ERROR                  ((kim_error_t) NULL)

/*!
 * \ingroup kim_types_reference
 * The kim_error_code_t for KIM_NO_ERROR. 
 */
#define KIM_NO_ERROR_ECODE            ((kim_error_code_t) 0)
    
/*!
 * \page kim_error_overview KIM Error Overview
 *
 * An error object.  Error objects consist of a machine readable error code for 
 * for programmatic error handling and a string describing the error.  All KIM APIs
 * return kim_errors with the exception of memory deallocation functions and the
 * kim_error_t APIs which return pieces of a kim_error_t object.  
 *
 * Functions which return successfully will return #KIM_NO_ERROR (NULL).  Because
 * #KIM_NO_ERROR does not need to be freed, you may use if-ladders or goto-style 
 * error handling when calling the KIM APIs.  In addition, kim_error_free() may 
 * be called on #KIM_NO_ERROR.
 *
 * \note Certain kim_error_t objects are preallocated by the libraries avoid 
 * exacerbating existing problems while trying to report an error.  For example,
 * the out of memory error object is preallocated.  It is safe to call 
 * #kim_error_free() on these errors, although the function may not actually free
 * the object.
 *
 * By providing an error object rather than a numeric code, the KIM APIs can 
 * tailor error strings to the circumstances of the error.  So rather than returning 
 * error strings like "Client not found in Kerberos database", we can report 
 * "'user@REALM' not found in Kerberos database" while still providing the machine
 * readable error KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN.
 *
 * See \ref kim_error_reference for information on specific APIs.
 */

/*!
 * \defgroup kim_error_reference KIM Error Reference Documentation
 * @{
 */

/*!
 * \param out_error on exit, a new error object which is a copy of \a in_error.  
 *      	    Must be freed with kim_error_free().
 * \param in_error  the error to copy.
 * \return On success, #KIM_NO_ERROR.  On failure, an error object representing the failure.
 * \brief Copy an error.
 */
kim_error_t kim_error_copy (kim_error_t *out_error,
                            kim_error_t  in_error);

/*!
 * \param in_error an error object.
 * \return On success, a machine-readable error code describing the error represented 
 *         by \a in_error. On failure, #KIM_PARAMETER_ECODE.
 * \brief Get a numerical error code for an error.
 */
kim_error_code_t kim_error_get_code (kim_error_t in_error);

/*!
 * \param in_error an error object.
 * \return On success, a human-readable error string describing the error represented 
 *         by \a in_error.  On failure, NULL, indicating that the kim_error_t object was
 *         invalid.
 * \brief Get a text description of an error.
 */
kim_string_t kim_error_get_display_string (kim_error_t in_error);

/*!
 * \param io_error the error object to be freed.  Set to NULL on exit.
 * \brief Free memory associated with an error.
 */
void kim_error_free (kim_error_t *io_error);

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_ERROR_H */
