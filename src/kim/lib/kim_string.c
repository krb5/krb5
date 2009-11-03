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

#include "kim_private.h"

const char kim_empty_string[1] = "";

/* ------------------------------------------------------------------------ */

kim_error kim_string_create_from_format (kim_string *out_string,
                                         kim_string  in_format,
                                         ...)
{
    kim_error err = kim_library_init ();
    va_list args;

    va_start (args, in_format);
    err = kim_string_create_from_format_va (out_string, in_format, args);
    va_end (args);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_string_create_from_format_va_retcode (kim_string *out_string,
                                                    kim_string  in_format,
                                                    va_list     in_args)
{
    kim_error err = kim_library_init ();

    int count = vasprintf ((char **) out_string, in_format, in_args);
    if (count < 0) { err = check_error (KIM_OUT_OF_MEMORY_ERR); }

    return err;
}

/* ------------------------------------------------------------------------ */

kim_error kim_string_create_from_format_va (kim_string *out_string,
                                            kim_string  in_format,
                                            va_list     in_args)
{
    kim_error err = kim_library_init ();
    kim_string string = NULL;

    if (!err && !out_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_format ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        err = kim_string_create_from_format_va_retcode (&string,
                                                        in_format,
                                                        in_args);
    }

    if (!err) {
        *out_string = string;
        string = NULL;
    }

    if (string) { kim_string_free (&string); }

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_string_create_from_buffer (kim_string *out_string,
                                         const char *in_buffer,
                                         kim_count   in_length)
{
    kim_error err = kim_library_init ();
    kim_string string = NULL;

    if (!err && !out_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_buffer ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        string = calloc (in_length + 1, sizeof (char *));
        if (!string) { err = check_error (KIM_OUT_OF_MEMORY_ERR); }
    }

    if (!err) {
        memcpy ((char *) string, in_buffer, in_length * sizeof (char));
        *out_string = string;
        string = NULL;
    }

    kim_string_free (&string);

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_string_create_for_last_error (kim_string *out_string,
                                            kim_error   in_error)
{
    kim_error err = kim_library_init ();

    err = kim_string_copy (out_string, kim_error_message (in_error));

    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_string_copy (kim_string *out_string,
                           kim_string  in_string)
{
    kim_error err = kim_library_init ();
    kim_string string = NULL;

    if (!err && !out_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_string ) { err = check_error (KIM_NULL_PARAMETER_ERR); }

    if (!err) {
        if (in_string[0]) {
            string = calloc (strlen (in_string) + 1, sizeof (char *));
            if (!string) { err = check_error (KIM_OUT_OF_MEMORY_ERR); }

            if (!err) {
                strncpy ((char *) string, in_string, strlen (in_string) + 1);
            }
        } else {
            string = kim_empty_string;
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

kim_error kim_string_compare (kim_string      in_string,
                              kim_string      in_compare_to_string,
                              kim_comparison *out_comparison)
{
    return kim_os_string_compare (in_string,
                                  in_compare_to_string,
                                  0, /* case sensitive */
                                  out_comparison);
}

/* ------------------------------------------------------------------------ */

void kim_string_free (kim_string *io_string)
{
    if (io_string && *io_string && *io_string != kim_empty_string) {
        free ((char *) *io_string);
        *io_string = NULL;
    }
}
