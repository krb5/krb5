/*
 * $Header$
 *
 * Copyright 2008 Massachusetts Institute of Technology.
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

#include "kim_private.h"

/* ------------------------------------------------------------------------ */

kim_error _check_error (kim_error  in_err,
                        kim_string in_function,
                        kim_string in_file,
                        int        in_line)
{
    if (in_err) {
        kim_debug_printf ("%s(): got %d ('%s') at %s: %d",
                          in_function, in_err, kim_error_message (in_err),
                          in_file, in_line);
    }

    return in_err;
}

/* ------------------------------------------------------------------------ */

void __kim_debug_printf (kim_string in_function,
                         kim_string in_format,
                         ...)
{
    kim_error err = KIM_NO_ERROR;
    kim_string format = NULL;
    kim_string string = NULL;

    if (!err && !in_function) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_format  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_string_create_from_format (&format, "%s(): %s",
                                             in_function, in_format);
    }

    if (!err) {
        va_list args;
        va_start (args, in_format);
        err = kim_string_create_from_format_va (&string, format, args);
        va_end (args);
    }

    if (!err) {
        kim_os_debug_print (string);
    }

    kim_string_free (&format);
    kim_string_free (&string);
}
