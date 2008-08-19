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
 */
#define KIM_NO_ERROR                  ((kim_error) 0)
    
/*!
 * \page kim_error_overview KIM Error Overview
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
 * call #kim_string_get_last_error_message() to obtain a copy of the  
 * descriptive error message.
 * 
 * Note that because this string is stored in thread-specific data, callers 
 * must call #kim_string_get_last_error_message() before calling any KIM APIs
 * or any other APIs which might call into KIM.  Callers who are not going
 * to display this error string immediately should also make a copy of it
 * so that it is not overwritten by the next call into KIM.
 *
 * See \ref kim_error_reference for information on specific APIs.
 */

/*!
 * \defgroup kim_error_reference KIM Error Reference Documentation
 * @{
 */

/*!
 * \param out_string On success, a human-readable UTF-8 string describing the 
 *                   error representedby \a in_error.  Must be freed with
 *                   kim_string_free()
 * \param in_error   an error code.
 * \return On success, KIM_NO_ERROR.  
 * \note This API returns thread local storage.  It should be called 
 * immediately after a KIM API returns an error so that the correct string
 * is returned.
 * \brief Get a text description of an error suitable for display to the user.
 */
kim_error kim_string_get_last_error_message (kim_string *out_string,
                                             kim_error   in_error);

/*!@}*/

#ifdef __cplusplus
}
#endif

#endif /* KIM_ERROR_H */
