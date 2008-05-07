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

#ifndef KIM_LIBRARY_PRIVATE_H
#define KIM_LIBRARY_PRIVATE_H

#include <kim/kim.h>


#define kim_debug_printf(format, ...) __kim_library_debug_printf(__FUNCTION__, format, ## __VA_ARGS__)
void __kim_library_debug_printf (kim_string_t in_function, 
                                 kim_string_t in_format, 
                                 ...);

kim_error_t kim_library_set_allow_home_directory_access (kim_boolean_t in_allow_access);

kim_error_t kim_library_get_allow_home_directory_access (kim_boolean_t *out_allow_access);

kim_boolean_t kim_library_allow_home_directory_access (void);

kim_error_t kim_library_set_allow_automatic_prompting (kim_boolean_t in_allow_automatic_prompting);

kim_error_t kim_library_get_allow_automatic_prompting (kim_boolean_t *out_allow_automatic_prompting);

kim_boolean_t kim_library_allow_automatic_prompting (void);

void kim_os_library_debug_print (kim_string_t in_string);

kim_boolean_t kim_os_library_caller_is_server (void);

#endif /* KIM_LIBRARY_PRIVATE_H */
