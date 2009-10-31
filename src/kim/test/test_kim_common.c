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

#include <test_kim_common.h>

const char *k_no_test_name = "No test name set";

/* ------------------------------------------------------------------------ */

int test_init (kim_test_state_t *out_state)
{
    kim_test_state_t state = NULL;

    printf ("Initializing tests... ");

    state = malloc (sizeof (*state));
    if (!state) {
        printf ("out of memory.\n\n");
        return 1;
    }

    state->test_name = k_no_test_name;
    state->global_fail_count = 0;
    state->test_fail_count = 0;

    *out_state = state;

    printf ("done.\n\n");

    return 0;
}

/* ------------------------------------------------------------------------ */

int test_cleanup (kim_test_state_t io_state)
{
    int global_fail_count = io_state->global_fail_count;

    printf ("Exiting.  %d total failures.", global_fail_count);
    free (io_state);

    return global_fail_count;
}

/* ------------------------------------------------------------------------ */

void start_test (kim_test_state_t in_state,
                 const char *in_test_name)
{
    in_state->test_name = in_test_name;
    in_state->test_fail_count = 0;

    printf ("Testing %s...\n", in_state->test_name);
}

/* ------------------------------------------------------------------------ */

void end_test (kim_test_state_t in_state)
{
    printf ("Finished testing %s.  %d failures.\n\n",
            in_state->test_name, in_state->test_fail_count);

    in_state->test_name = k_no_test_name;
    in_state->global_fail_count += in_state->test_fail_count;
    in_state->test_fail_count = 0;
}

/* ------------------------------------------------------------------------ */

void fail_if_error (kim_test_state_t  in_state,
                    const char       *in_function,
                    kim_error         in_err,
                    const char       *in_format,
                    ...)
{
    if (in_err) {
        va_list args;
        kim_string message = NULL;

        kim_error err = kim_string_create_for_last_error (&message, in_err);

        printf ("\tFAILURE: ");
        printf ("%s() got %d (%s) ",
                in_function, in_err, !err ? message : "Unknown");

        va_start (args, in_format);
        vprintf (in_format, args);
        va_end (args);

        printf ("\n");

        in_state->test_fail_count++;

        kim_string_free (&message);
    }
}

/* ------------------------------------------------------------------------ */

void log_failure (kim_test_state_t  in_state,
                  const char       *in_format,
                  ...)
{
    va_list args;

    printf ("\tFAILURE: ");

    va_start (args, in_format);
    vprintf (in_format, args);
    va_end (args);

    printf ("\n");

    in_state->test_fail_count++;
}
