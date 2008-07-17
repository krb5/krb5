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

#ifndef KIM_ERROR_PRIVATE_H
#define KIM_ERROR_PRIVATE_H

#include <kim/kim.h>

kim_error _kim_error_create_for_param (kim_string in_function, 
                                         unsigned int in_argument_position,
                                         kim_string in_argument_name,
                                         kim_string in_invalid_value);
#define param_error(pos, name, value) _kim_error_create_for_param(__FUNCTION__, \
                                                                  pos, name, value)

kim_error kim_error_create_from_code (kim_error_code in_code, 
                                        ...);
kim_error kim_error_create_from_code_va (kim_error_code in_code, 
                                           va_list args);

#define ccapi_error(code) kim_error_create_from_code(code)
#define krb5_error(code)  kim_error_create_from_code(code)
#define gss_error(code)   kim_error_create_from_code(code)
#define os_error(code)    kim_error_create_from_code(code)

kim_error _check_error (kim_error  in_err, 
                          kim_string in_function, 
                          kim_string in_file, 
                          int          in_line);
#define check_error(err) _check_error(err, __FUNCTION__, __FILE__, __LINE__)

#endif /* KIM_ERROR_PRIVATE_H */
